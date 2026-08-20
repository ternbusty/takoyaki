package com.ternbusty.takoyaki;

import com.ternbusty.takoyaki.command.CreateCommand;
import com.ternbusty.takoyaki.command.DeleteCommand;
import com.ternbusty.takoyaki.command.EventsCommand;
import com.ternbusty.takoyaki.command.FeaturesCommand;
import com.ternbusty.takoyaki.command.ExecCommand;
import com.ternbusty.takoyaki.command.KillCommand;
import com.ternbusty.takoyaki.command.ListCommand;
import com.ternbusty.takoyaki.command.PauseCommand;
import com.ternbusty.takoyaki.command.PsCommand;
import com.ternbusty.takoyaki.command.ResumeCommand;
import com.ternbusty.takoyaki.command.RunCommand;
import com.ternbusty.takoyaki.command.SpecCommand;
import com.ternbusty.takoyaki.command.StartCommand;
import com.ternbusty.takoyaki.command.StateCommand;
import com.ternbusty.takoyaki.command.UpdateCommand;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.process.ExecProcess;
import com.ternbusty.takoyaki.process.InitProcess;

import java.util.ArrayList;
import java.util.List;

/**
 * takoyaki CLI entry point — a hand-rolled argv dispatcher with no picocli.
 *
 * <p>Why no framework: picocli's {@code new CommandLine(rootCmd)} +
 * {@code execute()} cost ~80 ms on aarch64 native-image due to reflection-
 * over-annotations at every invocation. takoyaki runs as short-lived
 * orchestrator-invoked processes (~150 ms wall) where that's a 50 %+ tax.
 *
 * <p>The argv grammar is intentionally simple and runc-compatible:
 * {@code takoyaki [root-opts...] SUBCOMMAND [sub-args...]}.
 */
public final class Main {
    private static final String VERSION = "0.1.1";
    /** OCI runtime-spec version this build targets. */
    private static final String OCI_SPEC_VERSION = "1.0.2";

    public static void main(String[] args) {
        boolean trace = "1".equals(System.getenv("_TAKOYAKI_TRACE_STARTUP"));
        // Capture monotonic time AS EARLY AS POSSIBLE. We print all trace
        // lines together at the end of main() so warm-up of PrintStream /
        // Charset / Locale doesn't steal from the very first measurement.
        long t0 = trace ? System.nanoTime() : 0;

        // Stage-2 (post-bootstrap re-exec) is detected via the sentinel argv
        // we set when re-execing /proc/self/exe in bootstrap.c.
        if (args.length == 1 && "__init__".equals(args[0])) {
            if ("1".equals(System.getenv("_TAKOYAKI_BOOTSTRAP_DEBUG"))) {
                Logger.setLevel(Logger.Level.DEBUG);
            }
            InitProcess.run();
            return;
        }

        // Same trick for `exec`: ExecCommand re-execs /proc/self/exe with this
        // sentinel (in the host namespaces) and ExecProcess does setns + the
        // restriction sequence from a fresh process.
        if (args.length == 1 && "__exec__".equals(args[0])) {
            if ("1".equals(System.getenv("_TAKOYAKI_EXEC_DEBUG"))) {
                Logger.setLevel(Logger.Level.DEBUG);
            }
            ExecProcess.run();
            return;
        }

        // Single-arg --version is the hottest probe orchestrators issue. Cut
        // straight to the print to avoid even the small dispatch overhead.
        // Trace mode falls through so we can still measure the dispatch cost.
        if (args.length == 1 && "--version".equals(args[0]) && !trace) {
            printVersion();
            System.exit(0);
        }

        // Single pass over argv: apply root-level options (which Logger and
        // env-passing care about) and find where the subcommand starts.
        String rootPath = "/run/takoyaki";
        boolean debug = false;
        String logFile = null;
        String logFormat = null;
        String subName = null;
        int subStart = -1;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.isEmpty() || a.charAt(0) != '-') {
                subName = a;
                subStart = i + 1;
                break;
            }
            switch (a) {
                case "-h", "--help" -> { printRootHelp(); System.exit(0); }
                case "-v", "--version" -> { printVersion(); System.exit(0); }
                case "--debug" -> debug = true;
                case "--root" -> { if (i + 1 < args.length) rootPath = args[++i]; }
                case "--log" -> { if (i + 1 < args.length) logFile = args[++i]; }
                case "--log-format" -> { if (i + 1 < args.length) logFormat = args[++i]; }
                case "--systemd-cgroup" -> { /* runc compat: accepted, no-op */ }
                case "--rootless", "--criu" -> { if (i + 1 < args.length) i++; }
                default -> {
                    System.err.println("takoyaki: unknown option: " + a);
                    System.exit(1);
                }
            }
        }

        // Apply log configuration after all options are parsed (runc parity):
        //   --debug            → level=DEBUG, output=stderr
        //   --log FILE         → level=WARN,  output=FILE
        //   --debug --log FILE → level=DEBUG, output=FILE
        //   (neither)          → level=OFF (default, no log output)
        if (debug) Logger.setLevel(Logger.Level.DEBUG);
        if (logFile != null) {
            Logger.setLogFile(logFile);
            if (!debug) Logger.setLevel(Logger.Level.WARN);
        }
        if ("json".equalsIgnoreCase(logFormat)) {
            Logger.setFormat(Logger.Format.JSON);
        }

        if (subName == null) {
            printRootHelp();
            System.exit(0);
        }

        int exitCode = dispatch(subName, args, subStart, rootPath, debug);

        if (trace) {
            long t6 = System.nanoTime();
            System.err.printf("[trace] MAIN raw monotonic ns     : %d%n", t0);
            System.err.printf("[trace] TOTAL (main entry -> done): %7.3f ms%n", (t6 - t0) / 1e6);
        }
        System.exit(exitCode);
    }

    private static int dispatch(String subName, String[] args, int subStart,
                                String rootPath, boolean debug) {
        // Per-subcommand --help short-circuit.
        if (subStart < args.length
                && ("-h".equals(args[subStart]) || "--help".equals(args[subStart]))) {
            if (SUBCOMMAND_DESCRIPTIONS.containsKey(subName)) {
                printSubcommandHelp(subName);
                return 0;
            }
            System.err.println("No help topic for '" + subName + "'");
            return 1;
        }
        return switch (subName) {
            case "state" -> runWithId("state", args, subStart, rootPath, StateCommand::run);
            case "list", "ls" -> dispatchList(args, subStart, rootPath);
            case "kill" -> dispatchKill(args, subStart, rootPath);
            case "start" -> runWithId("start", args, subStart, rootPath, StartCommand::run);
            case "pause" -> runWithId("pause", args, subStart, rootPath, PauseCommand::run);
            case "resume" -> runWithId("resume", args, subStart, rootPath, ResumeCommand::run);
            case "delete" -> dispatchDelete(args, subStart, rootPath);
            case "ps" -> dispatchPs(args, subStart, rootPath);
            case "create" -> dispatchCreate(args, subStart, rootPath, debug);
            case "run" -> dispatchRun(args, subStart, rootPath, debug);
            case "update" -> dispatchUpdate(args, subStart, rootPath);
            case "events" -> dispatchEvents(args, subStart, rootPath);
            case "exec" -> dispatchExec(args, subStart, rootPath);
            case "spec" -> SpecCommand.run(args, subStart);
            case "features" -> FeaturesCommand.run();
            default -> {
                System.err.println("takoyaki: unknown command: " + subName);
                yield 1;
            }
        };
    }

    // ---- per-subcommand argv parsing & dispatch -----------------------

    /** A subcommand that takes exactly the state root and a container ID. */
    private interface IdCommand {
        int run(String rootPath, String id);
    }

    /** Dispatch for subcommands whose only argument is a container ID. */
    private static int runWithId(String sub, String[] args, int subStart, String rootPath,
                                 IdCommand cmd) {
        // takoyaki <sub> <id>
        if (subStart >= args.length) {
            System.err.println("takoyaki " + sub + ": missing container ID");
            return 1;
        }
        return cmd.run(rootPath, args[subStart]);
    }

    private static int dispatchList(String[] args, int subStart, String rootPath) {
        // takoyaki list [-f|--format json|table] [-q|--quiet]
        String format = "table";
        boolean quiet = false;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            if ("-f".equals(a) || "--format".equals(a)) {
                if (i + 1 >= args.length) {
                    System.err.println("takoyaki list: --format requires a value");
                    return 1;
                }
                format = args[++i];
            } else if ("-q".equals(a) || "--quiet".equals(a)) {
                quiet = true;
            } else {
                System.err.println("takoyaki list: unexpected arg: " + a);
                return 1;
            }
        }
        return ListCommand.run(rootPath, format, quiet);
    }

    private static int dispatchKill(String[] args, int subStart, String rootPath) {
        // takoyaki kill [-a|--all] <id> [signal]
        boolean all = false;
        String id = null;
        String sig = "SIGTERM";
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            if ("-a".equals(a) || "--all".equals(a)) {
                all = true;
            } else if (id == null && a.charAt(0) != '-') {
                id = a;
            } else if (id != null && a.charAt(0) != '-') {
                sig = a;
            } else {
                System.err.println("takoyaki kill: unexpected arg: " + a);
                return 1;
            }
        }
        if (id == null) {
            System.err.println("takoyaki kill: missing container ID");
            return 1;
        }
        return KillCommand.run(rootPath, id, sig, all);
    }

    private static int dispatchDelete(String[] args, int subStart, String rootPath) {
        // takoyaki delete [-f|--force] <id>
        boolean force = false;
        String id = null;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            if ("-f".equals(a) || "--force".equals(a)) {
                force = true;
            } else if (a.charAt(0) != '-' && id == null) {
                id = a;
            } else {
                System.err.println("takoyaki delete: unexpected arg: " + a);
                return 1;
            }
        }
        if (id == null) {
            System.err.println("takoyaki delete: missing container ID");
            return 1;
        }
        return DeleteCommand.run(rootPath, id, force);
    }

    private static int dispatchPs(String[] args, int subStart, String rootPath) {
        // takoyaki ps [-f|--format] <id> [PS_ARGS...]
        // Everything after the container ID is passed through to the host ps
        // command (runc behaviour).
        String format = "table";
        String id = null;
        List<String> psArgs = new ArrayList<>();
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            if (id != null) {
                // Everything after the container ID is a ps argument
                psArgs.add(a);
            } else if ("-f".equals(a) || "--format".equals(a)) {
                if (i + 1 >= args.length) {
                    System.err.println("takoyaki ps: --format requires a value");
                    return 1;
                }
                format = args[++i];
            } else if (a.charAt(0) != '-') {
                id = a;
            } else {
                System.err.println("takoyaki ps: unexpected arg: " + a);
                return 1;
            }
        }
        if (id == null) {
            System.err.println("takoyaki ps: missing container ID");
            return 1;
        }
        return PsCommand.run(rootPath, id, format, psArgs);
    }

    private static int dispatchCreate(String[] args, int subStart, String rootPath, boolean debug) {
        // takoyaki create [-b BUNDLE] [--pid-file P] [--console-socket S]
        //                 [--no-pivot] [--no-new-keyring] [--preserve-fds N] <id>
        CreateOptions o = parseCreateOptions("create", args, subStart, false);
        if (o == null) return 1;
        return CreateCommand.run(rootPath, debug, o.id, o.bundle, o.pidFile, o.consoleSocket,
                o.noPivot, o.noNewKeyring, o.preserveFds, o.pidfdSocket);
    }

    private static int dispatchRun(String[] args, int subStart, String rootPath, boolean debug) {
        // takoyaki run [-b BUNDLE] [-d|--detach] [--pid-file P]
        //              [--console-socket S] [--no-pivot] [--no-new-keyring]
        //              [--preserve-fds N] <id>
        //
        // Same args as create except --detach. Without --detach we wait for
        // the container init to exit and then delete the state.
        CreateOptions o = parseCreateOptions("run", args, subStart, true);
        if (o == null) return 1;
        return RunCommand.run(rootPath, debug, o.id, o.bundle, o.pidFile, o.consoleSocket,
                o.noPivot, o.noNewKeyring, o.preserveFds, o.detach, o.pidfdSocket);
    }

    /** Options shared by create and run (run additionally accepts -d/--detach). */
    private static final class CreateOptions {
        String bundle = ".";
        String pidFile = null;
        String consoleSocket = null;
        String pidfdSocket = null;
        boolean noPivot = false;
        boolean noNewKeyring = false;
        int preserveFds = 0;
        boolean detach = false;
        String id = null;
    }

    /**
     * Parses the create/run option grammar. Returns null (after printing the
     * error) when the argv is invalid.
     */
    private static CreateOptions parseCreateOptions(String sub, String[] args, int subStart,
                                                    boolean allowDetach) {
        CreateOptions o = new CreateOptions();
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-b", "--bundle" -> {
                    if (i + 1 >= args.length) { missingArg(sub, a); return null; }
                    o.bundle = args[++i];
                }
                case "-d", "--detach" -> {
                    if (!allowDetach) {
                        System.err.println("takoyaki " + sub + ": unexpected arg: " + a);
                        return null;
                    }
                    o.detach = true;
                }
                case "--pid-file" -> {
                    if (i + 1 >= args.length) { missingArg(sub, a); return null; }
                    o.pidFile = args[++i];
                }
                case "--console-socket" -> {
                    if (i + 1 >= args.length) { missingArg(sub, a); return null; }
                    o.consoleSocket = args[++i];
                }
                case "--pidfd-socket" -> {
                    if (i + 1 >= args.length) { missingArg(sub, a); return null; }
                    o.pidfdSocket = args[++i];
                }
                case "--no-pivot" -> o.noPivot = true;
                case "--no-new-keyring" -> o.noNewKeyring = true;
                case "--preserve-fds" -> {
                    if (i + 1 >= args.length) { missingArg(sub, a); return null; }
                    Integer v = parseIntOrFail(sub, a, args[++i]);
                    if (v == null) return null;
                    o.preserveFds = v;
                }
                default -> {
                    if (a.charAt(0) != '-' && o.id == null) {
                        o.id = a;
                    } else {
                        System.err.println("takoyaki " + sub + ": unexpected arg: " + a);
                        return null;
                    }
                }
            }
        }
        if (o.id == null) {
            System.err.println("takoyaki " + sub + ": missing container ID");
            return null;
        }
        return o;
    }

    private static int dispatchUpdate(String[] args, int subStart, String rootPath) {
        // takoyaki update [-r FILE|-] [--memory N] [--memory-reservation N]
        //   [--memory-swap N] [--cpu-quota N] [--cpu-period N]
        //   [--cpu-share N|--cpu-shares N] [--pids-limit N] [--cpuset-cpus S]
        //   [--cpu-burst N] [--cpu-idle N] <id>
        String resourcesPath = null;
        Long memory = null;
        Long memoryReservation = null;
        Long memorySwap = null;
        Long cpuQuota = null;
        Long cpuPeriod = null;
        Long cpuShares = null;
        Long pidsLimit = null;
        String cpusetCpus = null;
        Long cpuBurst = null;
        Long cpuIdle = null;
        String id = null;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-r", "--resources" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    String rval = args[++i];
                    if ("-".equals(rval)) {
                        // Read resources JSON from stdin
                        resourcesPath = readStdinToTempFile();
                        if (resourcesPath == null) return 1;
                    } else {
                        resourcesPath = rval;
                    }
                }
                case "--memory" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    memory = parseMemoryValue("update", a, args[++i]);
                    if (memory == null) return 1;
                }
                case "--memory-reservation" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    memoryReservation = parseMemoryValue("update", a, args[++i]);
                    if (memoryReservation == null) return 1;
                }
                case "--memory-swap" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    memorySwap = parseMemoryValue("update", a, args[++i]);
                    if (memorySwap == null) return 1;
                }
                case "--cpu-quota" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    cpuQuota = parseLongOrFail("update", a, args[++i]);
                    if (cpuQuota == null) return 1;
                }
                case "--cpu-period" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    cpuPeriod = parseLongOrFail("update", a, args[++i]);
                    if (cpuPeriod == null) return 1;
                }
                case "--cpu-share", "--cpu-shares" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    cpuShares = parseLongOrFail("update", a, args[++i]);
                    if (cpuShares == null) return 1;
                }
                case "--pids-limit" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    pidsLimit = parseLongOrFail("update", a, args[++i]);
                    if (pidsLimit == null) return 1;
                }
                case "--cpuset-cpus" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    cpusetCpus = args[++i];
                }
                case "--cpu-burst" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    cpuBurst = parseLongOrFail("update", a, args[++i]);
                    if (cpuBurst == null) return 1;
                }
                case "--cpu-idle" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    cpuIdle = parseLongOrFail("update", a, args[++i]);
                    if (cpuIdle == null) return 1;
                }
                default -> {
                    if (a.charAt(0) != '-' && id == null) {
                        id = a;
                    } else {
                        System.err.println("takoyaki update: unexpected arg: " + a);
                        return 1;
                    }
                }
            }
        }
        if (id == null) {
            System.err.println("takoyaki update: missing container ID");
            return 1;
        }
        return UpdateCommand.run(rootPath, id, resourcesPath, memory,
                memoryReservation, memorySwap, cpuQuota, cpuPeriod, cpuShares,
                pidsLimit, cpusetCpus, cpuBurst, cpuIdle);
    }

    /** Read stdin to a temp file and return its path. */
    private static String readStdinToTempFile() {
        try {
            byte[] data = System.in.readAllBytes();
            java.nio.file.Path tmp = java.nio.file.Files.createTempFile("takoyaki-update-", ".json");
            java.nio.file.Files.write(tmp, data);
            return tmp.toString();
        } catch (java.io.IOException e) {
            System.err.println("failed to read stdin: " + e.getMessage());
            return null;
        }
    }

    /** Parse a memory value that may have units (K, M, G) or be a plain number. */
    private static Long parseMemoryValue(String sub, String opt, String value) {
        if (value == null || value.isEmpty()) return null;
        // Check for -1 (unlimited)
        if ("-1".equals(value)) return -1L;
        // Human-readable suffixes (case-insensitive)
        String upper = value.toUpperCase();
        long multiplier = 1;
        String numPart = value;
        if (upper.endsWith("G")) {
            multiplier = 1024L * 1024 * 1024;
            numPart = value.substring(0, value.length() - 1);
        } else if (upper.endsWith("M")) {
            multiplier = 1024L * 1024;
            numPart = value.substring(0, value.length() - 1);
        } else if (upper.endsWith("K")) {
            multiplier = 1024L;
            numPart = value.substring(0, value.length() - 1);
        }
        try {
            return Long.parseLong(numPart) * multiplier;
        } catch (NumberFormatException e) {
            System.err.println("takoyaki " + sub + ": " + opt + " requires an integer, got: " + value);
            return null;
        }
    }

    private static int dispatchEvents(String[] args, int subStart, String rootPath) {
        // takoyaki events [--stats] [--interval DURATION] <id>
        boolean once = false;
        String interval = "5s";
        String id = null;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--stats" -> once = true;
                case "--interval" -> {
                    if (i + 1 >= args.length) return missingArg("events", a);
                    interval = args[++i];
                }
                default -> {
                    if (a.charAt(0) != '-' && id == null) {
                        id = a;
                    } else {
                        System.err.println("takoyaki events: unexpected arg: " + a);
                        return 1;
                    }
                }
            }
        }
        if (id == null) {
            System.err.println("takoyaki events: missing container ID");
            return 1;
        }
        return EventsCommand.run(rootPath, id, once, interval);
    }

    private static int dispatchExec(String[] args, int subStart, String rootPath) {
        // takoyaki exec [-p FILE] [-u UID[:GID]] [-t] [--cwd DIR] [-e KEY=VAL]...
        //               [--additional-gids GID]... [--preserve-fds N]
        //               [--cap CAP]... [--cgroup PATH] [--console-socket S]
        //               <id> [--] CMD [ARG...]
        String processJson = null;
        String user = null;
        String cwd = null;
        List<String> envs = new ArrayList<>();
        List<String> additionalGids = new ArrayList<>();
        List<String> caps = new ArrayList<>();
        String id = null;
        List<String> command = new ArrayList<>();
        boolean detach = false;
        boolean tty = false;
        String pidFile = null;
        int preserveFds = 0;
        String consoleSocket = null;
        String cgroupPath = null;
        String consoleSizeStr = null;
        String pidfdSocket = null;
        boolean ignorePaused = false;
        boolean afterPositional = false;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            if (afterPositional) {
                command.add(a);
                continue;
            }
            if ("--".equals(a)) {
                afterPositional = true;
                continue;
            }
            // Handle --flag=value form
            String flagKey = a;
            String flagVal = null;
            int eqIdx = a.indexOf('=');
            if (eqIdx > 0 && a.startsWith("--")) {
                flagKey = a.substring(0, eqIdx);
                flagVal = a.substring(eqIdx + 1);
            }
            switch (flagKey) {
                case "-p", "--process" -> {
                    if (flagVal != null) { processJson = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else processJson = args[++i];
                }
                case "-u", "--user" -> {
                    if (flagVal != null) { user = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else user = args[++i];
                }
                case "-d", "--detach" -> detach = true;
                case "--pid-file" -> {
                    if (flagVal != null) { pidFile = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else pidFile = args[++i];
                }
                case "--console-socket" -> {
                    if (flagVal != null) { consoleSocket = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else consoleSocket = args[++i];
                }
                case "-t", "--tty" -> tty = true;
                case "--cwd" -> {
                    if (flagVal != null) { cwd = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else cwd = args[++i];
                }
                case "-e", "--env" -> {
                    if (flagVal != null) { envs.add(flagVal); }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else envs.add(args[++i]);
                }
                case "--additional-gids" -> {
                    if (flagVal != null) { additionalGids.add(flagVal); }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else additionalGids.add(args[++i]);
                }
                case "--preserve-fds" -> {
                    String val = flagVal != null ? flagVal : (i + 1 < args.length ? args[++i] : null);
                    if (val == null) return missingArg("exec", a);
                    Integer v = parseIntOrFail("exec", "--preserve-fds", val);
                    if (v == null) return 1;
                    preserveFds = v;
                }
                case "--cap" -> {
                    if (flagVal != null) { caps.add(flagVal); }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else caps.add(args[++i]);
                }
                case "--cgroup" -> {
                    if (flagVal != null) { cgroupPath = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else cgroupPath = args[++i];
                }
                case "--console-size" -> {
                    if (flagVal != null) { consoleSizeStr = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else consoleSizeStr = args[++i];
                }
                case "--ignore-paused" -> ignorePaused = true;
                case "--pidfd-socket" -> {
                    if (flagVal != null) { pidfdSocket = flagVal; }
                    else if (i + 1 >= args.length) return missingArg("exec", a);
                    else pidfdSocket = args[++i];
                }
                case "--no-new-privs" -> { /* accepted for compat, always-on in takoyaki */ }
                case "--apparmor", "--process-label" -> {
                    // Accept and skip these flags with their values
                    if (flagVal == null && i + 1 < args.length) i++;
                }
                default -> {
                    if (a.charAt(0) != '-' && id == null) {
                        id = a;
                        afterPositional = true; // everything after = the command
                    } else {
                        System.err.println("takoyaki exec: unexpected arg: " + a);
                        return 1;
                    }
                }
            }
        }
        if (id == null) {
            System.err.println("takoyaki exec: missing container ID");
            return 1;
        }
        if (processJson == null && command.isEmpty()) {
            System.err.println("takoyaki exec: no command specified");
            return 1;
        }
        // runc compat: --cgroup must not escape to parent (.. components).
        // "/" is allowed (means top-level cgroup, the default).
        if (cgroupPath != null && !"/".equals(cgroupPath)) {
            if (cgroupPath.contains("..")) {
                System.err.println("bad sub cgroup path \"" + cgroupPath + "\"");
                return 1;
            }
        }
        // Parse --console-size WIDTH:HEIGHT (runc uses WIDTH:HEIGHT order)
        Spec.Box consoleSize = null;
        if (consoleSizeStr != null) {
            String[] parts = consoleSizeStr.split(":");
            if (parts.length == 2) {
                try {
                    consoleSize = new Spec.Box();
                    consoleSize.width = Integer.parseInt(parts[0]);
                    consoleSize.height = Integer.parseInt(parts[1]);
                } catch (NumberFormatException e) {
                    System.err.println("takoyaki exec: bad console-size: " + consoleSizeStr);
                    return 1;
                }
            }
        }
        return ExecCommand.run(rootPath, id, processJson, user, cwd, envs, command,
                detach, pidFile, tty, consoleSocket, additionalGids, caps,
                preserveFds, cgroupPath, consoleSize, ignorePaused, pidfdSocket);
    }

    // ---- small helpers ------------------------------------------------

    private static int missingArg(String sub, String opt) {
        System.err.println("takoyaki " + sub + ": " + opt + " requires a value");
        return 1;
    }

    private static Long parseLongOrFail(String sub, String opt, String value) {
        try { return Long.parseLong(value); }
        catch (NumberFormatException e) {
            System.err.println("takoyaki " + sub + ": " + opt + " requires an integer, got: " + value);
            return null;
        }
    }

    // Int twin of parseLongOrFail. Kept separate because the historical int
    // sites print a shorter message (no ", got: <value>" suffix) and callers
    // depend on that exact output.
    private static Integer parseIntOrFail(String sub, String opt, String value) {
        try { return Integer.parseInt(value); }
        catch (NumberFormatException e) {
            System.err.println("takoyaki " + sub + ": " + opt + " requires an integer");
            return null;
        }
    }

    // ---- help text (runc-compatible format) ----------------------------

    /** Subcommand descriptions used for NAME: help blocks and for validating
     *  known subcommands. Includes runc subcommands that takoyaki does not
     *  implement (checkpoint, restore, features) so that {@code runc <sub> -h}
     *  still prints a NAME: block instead of "No help topic". */
    private static final java.util.Map<String, String> SUBCOMMAND_DESCRIPTIONS = java.util.Map.ofEntries(
            java.util.Map.entry("create", "create a container"),
            java.util.Map.entry("run", "create and run a container"),
            java.util.Map.entry("start", "start a created container"),
            java.util.Map.entry("state", "output the state of a container"),
            java.util.Map.entry("kill", "send a signal to a container"),
            java.util.Map.entry("delete", "delete any resources held by the container"),
            java.util.Map.entry("list", "lists containers"),
            java.util.Map.entry("ls", "lists containers"),
            java.util.Map.entry("ps", "ps displays the processes running inside a container"),
            java.util.Map.entry("pause", "pause suspends all processes inside the container"),
            java.util.Map.entry("resume", "resumes all processes that have been previously paused"),
            java.util.Map.entry("update", "update container resource constraints"),
            java.util.Map.entry("events", "display container events such as OOM notifications and stats"),
            java.util.Map.entry("exec", "execute new process inside the container"),
            java.util.Map.entry("spec", "create a new specification file"),
            java.util.Map.entry("checkpoint", "checkpoint a running container"),
            java.util.Map.entry("restore", "restore a container from a previous checkpoint"),
            java.util.Map.entry("features", "show the enabled features")
    );

    private static void printVersion() {
        System.out.println("runc version " + VERSION);
        System.out.println("commit: (none)");
        System.out.println("spec: " + OCI_SPEC_VERSION);
    }

    private static void printRootHelp() {
        // runc-compatible NAME:/USAGE: format so bats tests match.
        System.out.println("""
                NAME:
                   runc - Open Container Initiative runtime

                USAGE:
                   runc [global options] command [command options] [arguments...]

                COMMANDS:
                   checkpoint  checkpoint a running container
                   create      create a container
                   delete      delete any resources held by the container
                   events      display container events such as OOM notifications and stats
                   exec        execute new process inside the container
                   kill        send a signal to a container
                   list        lists containers
                   pause       pause suspends all processes inside the container
                   ps          ps displays the processes running inside a container
                   restore     restore a container from a previous checkpoint
                   resume      resumes all processes that have been previously paused
                   run         create and run a container
                   spec        create a new specification file
                   start       start a created container
                   state       output the state of a container
                   update      update container resource constraints

                GLOBAL OPTIONS:
                   --debug             enable debug logging
                   --log value         set the log file to write runc logs to (default is '/dev/stderr')
                   --log-format value  set the log format ('text' (default), or 'json') (default: "text")
                   --root value        root directory for storage of container state (default: "/run/runc")
                   --systemd-cgroup    enable systemd cgroup support
                   --rootless value    (ignored)
                   --criu value        (ignored)
                   --help, -h          show help
                   --version, -v       print the version""");
    }

    private static void printSubcommandHelp(String sub) {
        String desc = SUBCOMMAND_DESCRIPTIONS.getOrDefault(sub, sub);
        System.out.println("NAME:");
        System.out.println("   runc " + sub + " - " + desc);
    }
}
