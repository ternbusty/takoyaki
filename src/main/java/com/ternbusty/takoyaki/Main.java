package com.ternbusty.takoyaki;

import com.ternbusty.takoyaki.command.CreateCommand;
import com.ternbusty.takoyaki.command.DeleteCommand;
import com.ternbusty.takoyaki.command.EventsCommand;
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
    private static final String VERSION_STRING = "takoyaki 0.1.1";

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
            System.out.println(VERSION_STRING);
            System.exit(0);
        }

        // Single pass over argv: apply root-level options (which Logger and
        // env-passing care about) and find where the subcommand starts.
        String rootPath = "/run/takoyaki";
        boolean debug = false;
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
                case "-v", "--version" -> { System.out.println(VERSION_STRING); System.exit(0); }
                case "--debug" -> { debug = true; Logger.setLevel(Logger.Level.DEBUG); }
                case "--root" -> { if (i + 1 < args.length) rootPath = args[++i]; }
                case "--log" -> { if (i + 1 < args.length) Logger.setLogFile(args[++i]); }
                case "--log-format" -> {
                    if (i + 1 < args.length && "json".equalsIgnoreCase(args[++i])) {
                        Logger.setFormat(Logger.Format.JSON);
                    }
                }
                case "--systemd-cgroup" -> { /* runc compat: accepted, no-op */ }
                case "--rootless", "--criu" -> { if (i + 1 < args.length) i++; }
                default -> {
                    System.err.println("takoyaki: unknown option: " + a);
                    System.exit(1);
                }
            }
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
        // Per-subcommand --help short-circuit. Each command's help is a tiny
        // canned string; we don't try to render the runc help layout exactly.
        if (subStart < args.length
                && ("-h".equals(args[subStart]) || "--help".equals(args[subStart]))) {
            printSubcommandHelp(subName);
            return 0;
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
        // takoyaki kill <id> [signal]
        if (subStart >= args.length) {
            System.err.println("takoyaki kill: missing container ID");
            return 1;
        }
        String id = args[subStart];
        String sig = subStart + 1 < args.length ? args[subStart + 1] : "SIGTERM";
        return KillCommand.run(rootPath, id, sig);
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
        // takoyaki ps [-f|--format] <id>
        String format = "table";
        String id = null;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            if ("-f".equals(a) || "--format".equals(a)) {
                if (i + 1 >= args.length) {
                    System.err.println("takoyaki ps: --format requires a value");
                    return 1;
                }
                format = args[++i];
            } else if (a.charAt(0) != '-' && id == null) {
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
        return PsCommand.run(rootPath, id, format);
    }

    private static int dispatchCreate(String[] args, int subStart, String rootPath, boolean debug) {
        // takoyaki create [-b BUNDLE] [--pid-file P] [--console-socket S]
        //                 [--no-pivot] [--no-new-keyring] [--preserve-fds N] <id>
        CreateOptions o = parseCreateOptions("create", args, subStart, false);
        if (o == null) return 1;
        return CreateCommand.run(rootPath, debug, o.id, o.bundle, o.pidFile, o.consoleSocket,
                o.noPivot, o.noNewKeyring, o.preserveFds);
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
                o.noPivot, o.noNewKeyring, o.preserveFds, o.detach);
    }

    /** Options shared by create and run (run additionally accepts -d/--detach). */
    private static final class CreateOptions {
        String bundle = ".";
        String pidFile = null;
        String consoleSocket = null;
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
        // takoyaki update [-r FILE] [--memory N] [--cpu-quota N] [--cpu-period N]
        //                 [--cpu-shares N] [--pids-limit N] <id>
        String resourcesPath = null;
        Long memory = null;
        Long cpuQuota = null;
        Long cpuPeriod = null;
        Long cpuShares = null;
        Long pidsLimit = null;
        String id = null;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-r", "--resources" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    resourcesPath = args[++i];
                }
                case "--memory" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    memory = parseLongOrFail("update", a, args[++i]);
                    if (memory == null) return 1;
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
                case "--cpu-shares" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    cpuShares = parseLongOrFail("update", a, args[++i]);
                    if (cpuShares == null) return 1;
                }
                case "--pids-limit" -> {
                    if (i + 1 >= args.length) return missingArg("update", a);
                    pidsLimit = parseLongOrFail("update", a, args[++i]);
                    if (pidsLimit == null) return 1;
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
                cpuQuota, cpuPeriod, cpuShares, pidsLimit);
    }

    private static int dispatchEvents(String[] args, int subStart, String rootPath) {
        // takoyaki events [--stats] [--interval SEC] <id>
        boolean once = false;
        int intervalSec = 5;
        String id = null;
        for (int i = subStart; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--stats" -> once = true;
                case "--interval" -> {
                    if (i + 1 >= args.length) return missingArg("events", a);
                    Integer v = parseIntOrFail("events", a, args[++i]);
                    if (v == null) return 1;
                    intervalSec = v;
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
        return EventsCommand.run(rootPath, id, once, intervalSec);
    }

    private static int dispatchExec(String[] args, int subStart, String rootPath) {
        // takoyaki exec [-p FILE] [-u UID[:GID]] [-t] [--cwd DIR] [-e KEY=VAL]... <id> [--] CMD [ARG...]
        // We treat the first non-flag positional as the container ID and
        // everything after it (or after a literal "--") as the command + args.
        // With -p (the containerd path) the process document replaces the
        // flags and command entirely, so no command is expected.
        String processJson = null;
        String user = null;
        String cwd = null;
        List<String> envs = new ArrayList<>();
        String id = null;
        List<String> command = new ArrayList<>();
        boolean detach = false;
        String pidFile = null;
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
            switch (a) {
                case "-p", "--process" -> {
                    if (i + 1 >= args.length) return missingArg("exec", a);
                    processJson = args[++i];
                }
                case "-u", "--user" -> {
                    if (i + 1 >= args.length) return missingArg("exec", a);
                    user = args[++i];
                }
                case "-d", "--detach" -> detach = true;
                case "--pid-file" -> {
                    if (i + 1 >= args.length) return missingArg("exec", a);
                    pidFile = args[++i];
                }
                case "--console-socket" -> {
                    if (i + 1 >= args.length) return missingArg("exec", a);
                    i++;
                    Logger.warn("exec: --console-socket is not supported yet, ignoring");
                }
                case "-t", "--tty" -> Logger.warn("exec: -t/--tty is not supported yet, ignoring");
                case "--cwd" -> {
                    if (i + 1 >= args.length) return missingArg("exec", a);
                    cwd = args[++i];
                }
                case "-e", "--env" -> {
                    if (i + 1 >= args.length) return missingArg("exec", a);
                    envs.add(args[++i]);
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
        return ExecCommand.run(rootPath, id, processJson, user, cwd, envs, command,
                detach, pidFile);
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

    // ---- help text ----------------------------------------------------

    private static void printRootHelp() {
        // Intentionally terse — runc / youki ship far more text but our
        // surface is small and this fits a single screen.
        System.out.println("""
                Usage: takoyaki [root-opts] SUBCOMMAND [args...]

                Root options:
                  --root PATH          State directory (default /run/takoyaki)
                  --debug              Enable debug logging
                  --log PATH           Log file path
                  --log-format FORMAT  text|json
                  --systemd-cgroup     (accepted, no-op)
                  --rootless VAL       (accepted)
                  --criu PATH          (accepted)
                  -v, --version        Print version
                  -h, --help           Print this help

                Subcommands:
                  create               Create a new container
                  run                  Create + start + wait + delete in one process
                  start                Start a created container
                  state                Display container state
                  kill                 Send a signal to a container
                  delete               Delete a container
                  list, ls             List containers
                  ps                   List processes in a container
                  pause                Pause a container
                  resume               Resume a paused container
                  update               Update container resources
                  events               Stream container stats
                  exec                 Run a command in a running container
                """);
    }

    private static void printSubcommandHelp(String sub) {
        String body = switch (sub) {
            case "create" -> "Usage: takoyaki create [-b BUNDLE] [--pid-file P] [--console-socket S] [--no-pivot] [--no-new-keyring] [--preserve-fds N] <id>";
            case "run" -> "Usage: takoyaki run [-b BUNDLE] [-d|--detach] [--pid-file P] [--console-socket S] [--no-pivot] [--no-new-keyring] [--preserve-fds N] <id>";
            case "start" -> "Usage: takoyaki start <id>";
            case "state" -> "Usage: takoyaki state <id>";
            case "kill" -> "Usage: takoyaki kill <id> [SIGNAL]";
            case "delete" -> "Usage: takoyaki delete [-f|--force] <id>";
            case "list", "ls" -> "Usage: takoyaki list [-f table|json] [-q|--quiet]";
            case "ps" -> "Usage: takoyaki ps [-f table|json] <id>";
            case "pause" -> "Usage: takoyaki pause <id>";
            case "resume" -> "Usage: takoyaki resume <id>";
            case "update" -> "Usage: takoyaki update [-r FILE] [--memory N] [--cpu-quota N] [--cpu-period N] [--cpu-shares N] [--pids-limit N] <id>";
            case "events" -> "Usage: takoyaki events [--stats] [--interval SEC] <id>";
            case "exec" -> "Usage: takoyaki exec [-p FILE] [-u UID[:GID]] [-t] [--cwd DIR] [-e KEY=VAL]... [-d] [--pid-file FILE] <id> CMD [ARG...]";
            default -> "Usage: takoyaki " + sub;
        };
        System.out.println(body);
    }
}
