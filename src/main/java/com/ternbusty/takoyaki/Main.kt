package com.ternbusty.takoyaki

import com.ternbusty.takoyaki.command.CreateCommand
import com.ternbusty.takoyaki.command.DeleteCommand
import com.ternbusty.takoyaki.command.EventsCommand
import com.ternbusty.takoyaki.command.ExecCommand
import com.ternbusty.takoyaki.command.FeaturesCommand
import com.ternbusty.takoyaki.command.KillCommand
import com.ternbusty.takoyaki.command.ListCommand
import com.ternbusty.takoyaki.command.PauseCommand
import com.ternbusty.takoyaki.command.PsCommand
import com.ternbusty.takoyaki.command.ResumeCommand
import com.ternbusty.takoyaki.command.RunCommand
import com.ternbusty.takoyaki.command.SpecCommand
import com.ternbusty.takoyaki.command.StartCommand
import com.ternbusty.takoyaki.command.StateCommand
import com.ternbusty.takoyaki.command.UpdateCommand
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.process.ExecProcess
import com.ternbusty.takoyaki.process.InitProcess
import java.io.IOException
import java.nio.file.Files
import kotlin.system.exitProcess

/**
 * takoyaki CLI entry point — a hand-rolled argv dispatcher with no picocli.
 *
 * Why no framework: picocli's `new CommandLine(rootCmd)` +
 * `execute()` cost ~80 ms on aarch64 native-image due to reflection-
 * over-annotations at every invocation. takoyaki runs as short-lived
 * orchestrator-invoked processes (~150 ms wall) where that's a 50 %+ tax.
 *
 * The argv grammar is intentionally simple and runc-compatible:
 * `takoyaki [root-opts...] SUBCOMMAND [sub-args...]`.
 */
class Main {
    companion object {
        private const val VERSION = "0.1.1"
        /** OCI runtime-spec version this build targets. */
        private const val OCI_SPEC_VERSION = "1.0.2"

        fun main(args: Array<String>) {
            val trace = System.getenv("_TAKOYAKI_TRACE_STARTUP") == "1"
            // Capture monotonic time AS EARLY AS POSSIBLE. We print all trace
            // lines together at the end of main() so warm-up of PrintStream /
            // Charset / Locale doesn't steal from the very first measurement.
            val t0 = if (trace) System.nanoTime() else 0L

            // Stage-2 (post-bootstrap re-exec) is detected via the sentinel argv
            // we set when re-execing /proc/self/exe in bootstrap.c.
            if (args.size == 1 && args[0] == "__init__") {
                if (System.getenv("_TAKOYAKI_BOOTSTRAP_DEBUG") == "1") {
                    Logger.level = Logger.Level.DEBUG
                }
                InitProcess.run()
                return
            }

            // Same trick for `exec`: ExecCommand re-execs /proc/self/exe with this
            // sentinel (in the host namespaces) and ExecProcess does setns + the
            // restriction sequence from a fresh process.
            if (args.size == 1 && args[0] == "__exec__") {
                if (System.getenv("_TAKOYAKI_EXEC_DEBUG") == "1") {
                    Logger.level = Logger.Level.DEBUG
                }
                ExecProcess.run()
                return
            }

            // Single-arg --version is the hottest probe orchestrators issue. Cut
            // straight to the print to avoid even the small dispatch overhead.
            // Trace mode falls through so we can still measure the dispatch cost.
            if (args.size == 1 && args[0] == "--version" && !trace) {
                printVersion()
                exitProcess(0)
            }

            // Single pass over argv: apply root-level options (which Logger and
            // env-passing care about) and find where the subcommand starts.
            var rootPath = "/run/takoyaki"
            var debug = false
            var logFile: String? = null
            var logFormat: String? = null
            var subName: String? = null
            var subStart = -1
            var i = 0
            while (i < args.size) {
                val a = args[i]
                if (a.isEmpty() || a[0] != '-') {
                    subName = a
                    subStart = i + 1
                    break
                }
                when (a) {
                    "-h", "--help" -> { printRootHelp(); exitProcess(0) }
                    "-v", "--version" -> { printVersion(); exitProcess(0) }
                    "--debug" -> debug = true
                    "--root" -> { if (i + 1 < args.size) rootPath = args[++i] }
                    "--log" -> { if (i + 1 < args.size) logFile = args[++i] }
                    "--log-format" -> { if (i + 1 < args.size) logFormat = args[++i] }
                    "--systemd-cgroup" -> { /* runc compat: accepted, no-op */ }
                    "--rootless", "--criu" -> { if (i + 1 < args.size) i++ }
                    else -> {
                        System.err.println("takoyaki: unknown option: $a")
                        exitProcess(1)
                    }
                }
                i++
            }

            // Apply log configuration after all options are parsed (runc parity):
            //   --debug            -> level=DEBUG, output=stderr
            //   --log FILE         -> level=WARN,  output=FILE
            //   --debug --log FILE -> level=DEBUG, output=FILE
            //   (neither)          -> level=OFF (default, no log output)
            if (debug) Logger.level = Logger.Level.DEBUG
            if (logFile != null) {
                Logger.setLogFile(logFile)
                if (!debug) Logger.level = Logger.Level.WARN
            }
            if (logFormat.equals("json", ignoreCase = true)) {
                Logger.format = Logger.Format.JSON
            }

            if (subName == null) {
                printRootHelp()
                exitProcess(0)
            }

            val exitCode = dispatch(subName, args, subStart, rootPath, debug)

            if (trace) {
                val t6 = System.nanoTime()
                System.err.printf("[trace] MAIN raw monotonic ns     : %d%n", t0)
                System.err.printf("[trace] TOTAL (main entry -> done): %7.3f ms%n", (t6 - t0) / 1e6)
            }
            exitProcess(exitCode)
        }

        private fun dispatch(
            subName: String, args: Array<String>, subStart: Int,
            rootPath: String, debug: Boolean
        ): Int {
            // Per-subcommand --help short-circuit.
            if (subStart < args.size
                && (args[subStart] == "-h" || args[subStart] == "--help")
            ) {
                if (subName in SUBCOMMAND_DESCRIPTIONS) {
                    printSubcommandHelp(subName)
                    return 0
                }
                System.err.println("No help topic for '$subName'")
                return 1
            }
            return when (subName) {
                "state" -> runWithId("state", args, subStart, rootPath, StateCommand::run)
                "list", "ls" -> dispatchList(args, subStart, rootPath)
                "kill" -> dispatchKill(args, subStart, rootPath)
                "start" -> runWithId("start", args, subStart, rootPath, StartCommand::run)
                "pause" -> runWithId("pause", args, subStart, rootPath, PauseCommand::run)
                "resume" -> runWithId("resume", args, subStart, rootPath, ResumeCommand::run)
                "delete" -> dispatchDelete(args, subStart, rootPath)
                "ps" -> dispatchPs(args, subStart, rootPath)
                "create" -> dispatchCreate(args, subStart, rootPath, debug)
                "run" -> dispatchRun(args, subStart, rootPath, debug)
                "update" -> dispatchUpdate(args, subStart, rootPath)
                "events" -> dispatchEvents(args, subStart, rootPath)
                "exec" -> dispatchExec(args, subStart, rootPath)
                "spec" -> SpecCommand.run(args, subStart)
                "features" -> FeaturesCommand.run()
                else -> {
                    System.err.println("takoyaki: unknown command: $subName")
                    1
                }
            }
        }

        // ---- per-subcommand argv parsing & dispatch -----------------------

        /** A subcommand that takes exactly the state root and a container ID. */
        private fun interface IdCommand {
            fun run(rootPath: String, id: String): Int
        }

        /** Dispatch for subcommands whose only argument is a container ID. */
        private fun runWithId(
            sub: String, args: Array<String>, subStart: Int, rootPath: String,
            cmd: IdCommand
        ): Int {
            // takoyaki <sub> <id>
            if (subStart >= args.size) {
                System.err.println("takoyaki $sub: missing container ID")
                return 1
            }
            return cmd.run(rootPath, args[subStart])
        }

        private fun dispatchList(args: Array<String>, subStart: Int, rootPath: String): Int {
            // takoyaki list [-f|--format json|table] [-q|--quiet]
            var format = "table"
            var quiet = false
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                if (a == "-f" || a == "--format") {
                    if (i + 1 >= args.size) {
                        System.err.println("takoyaki list: --format requires a value")
                        return 1
                    }
                    format = args[++i]
                } else if (a == "-q" || a == "--quiet") {
                    quiet = true
                } else {
                    System.err.println("takoyaki list: unexpected arg: $a")
                    return 1
                }
                i++
            }
            return ListCommand.run(rootPath, format, quiet)
        }

        private fun dispatchKill(args: Array<String>, subStart: Int, rootPath: String): Int {
            // takoyaki kill [-a|--all] <id> [signal]
            var all = false
            var id: String? = null
            var sig = "SIGTERM"
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                if (a == "-a" || a == "--all") {
                    all = true
                } else if (id == null && a[0] != '-') {
                    id = a
                } else if (id != null && a[0] != '-') {
                    sig = a
                } else {
                    System.err.println("takoyaki kill: unexpected arg: $a")
                    return 1
                }
                i++
            }
            if (id == null) {
                System.err.println("takoyaki kill: missing container ID")
                return 1
            }
            return KillCommand.run(rootPath, id, sig, all)
        }

        private fun dispatchDelete(args: Array<String>, subStart: Int, rootPath: String): Int {
            // takoyaki delete [-f|--force] <id>
            var force = false
            var id: String? = null
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                if (a == "-f" || a == "--force") {
                    force = true
                } else if (a[0] != '-' && id == null) {
                    id = a
                } else {
                    System.err.println("takoyaki delete: unexpected arg: $a")
                    return 1
                }
                i++
            }
            if (id == null) {
                System.err.println("takoyaki delete: missing container ID")
                return 1
            }
            return DeleteCommand.run(rootPath, id, force)
        }

        private fun dispatchPs(args: Array<String>, subStart: Int, rootPath: String): Int {
            // takoyaki ps [-f|--format] <id> [PS_ARGS...]
            // Everything after the container ID is passed through to the host ps
            // command (runc behaviour).
            var format = "table"
            var id: String? = null
            val psArgs = mutableListOf<String>()
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                if (id != null) {
                    // Everything after the container ID is a ps argument
                    psArgs.add(a)
                } else if (a == "-f" || a == "--format") {
                    if (i + 1 >= args.size) {
                        System.err.println("takoyaki ps: --format requires a value")
                        return 1
                    }
                    format = args[++i]
                } else if (a[0] != '-') {
                    id = a
                } else {
                    System.err.println("takoyaki ps: unexpected arg: $a")
                    return 1
                }
                i++
            }
            if (id == null) {
                System.err.println("takoyaki ps: missing container ID")
                return 1
            }
            return PsCommand.run(rootPath, id, format, psArgs)
        }

        private fun dispatchCreate(
            args: Array<String>, subStart: Int, rootPath: String, debug: Boolean
        ): Int {
            // takoyaki create [-b BUNDLE] [--pid-file P] [--console-socket S]
            //                 [--no-pivot] [--no-new-keyring] [--preserve-fds N] <id>
            val o = parseCreateOptions("create", args, subStart, false) ?: return 1
            return CreateCommand.run(
                rootPath, debug, o.id ?: return 1, o.bundle, o.pidFile, o.consoleSocket,
                o.noPivot, o.noNewKeyring, o.preserveFds, o.pidfdSocket
            )
        }

        private fun dispatchRun(
            args: Array<String>, subStart: Int, rootPath: String, debug: Boolean
        ): Int {
            // takoyaki run [-b BUNDLE] [-d|--detach] [--pid-file P]
            //              [--console-socket S] [--no-pivot] [--no-new-keyring]
            //              [--preserve-fds N] <id>
            //
            // Same args as create except --detach. Without --detach we wait for
            // the container init to exit and then delete the state.
            val o = parseCreateOptions("run", args, subStart, true) ?: return 1
            return RunCommand.run(
                rootPath, debug, o.id ?: return 1, o.bundle, o.pidFile, o.consoleSocket,
                o.noPivot, o.noNewKeyring, o.preserveFds, o.detach, o.pidfdSocket
            )
        }

        /** Options shared by create and run (run additionally accepts -d/--detach). */
        private class CreateOptions {
            var bundle = "."
            var pidFile: String? = null
            var consoleSocket: String? = null
            var pidfdSocket: String? = null
            var noPivot = false
            var noNewKeyring = false
            var preserveFds = 0
            var detach = false
            var id: String? = null
        }

        /**
         * Parses the create/run option grammar. Returns null (after printing the
         * error) when the argv is invalid.
         */
        private fun parseCreateOptions(
            sub: String, args: Array<String>, subStart: Int, allowDetach: Boolean
        ): CreateOptions? {
            val o = CreateOptions()
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                when (a) {
                    "-b", "--bundle" -> {
                        if (i + 1 >= args.size) { missingArg(sub, a); return null }
                        o.bundle = args[++i]
                    }
                    "-d", "--detach" -> {
                        if (!allowDetach) {
                            System.err.println("takoyaki $sub: unexpected arg: $a")
                            return null
                        }
                        o.detach = true
                    }
                    "--pid-file" -> {
                        if (i + 1 >= args.size) { missingArg(sub, a); return null }
                        o.pidFile = args[++i]
                    }
                    "--console-socket" -> {
                        if (i + 1 >= args.size) { missingArg(sub, a); return null }
                        o.consoleSocket = args[++i]
                    }
                    "--pidfd-socket" -> {
                        if (i + 1 >= args.size) { missingArg(sub, a); return null }
                        o.pidfdSocket = args[++i]
                    }
                    "--no-pivot" -> o.noPivot = true
                    "--no-new-keyring" -> o.noNewKeyring = true
                    "--preserve-fds" -> {
                        if (i + 1 >= args.size) { missingArg(sub, a); return null }
                        val v = parseIntOrFail(sub, a, args[++i]) ?: return null
                        o.preserveFds = v
                    }
                    else -> {
                        if (a[0] != '-' && o.id == null) {
                            o.id = a
                        } else {
                            System.err.println("takoyaki $sub: unexpected arg: $a")
                            return null
                        }
                    }
                }
                i++
            }
            if (o.id == null) {
                System.err.println("takoyaki $sub: missing container ID")
                return null
            }
            return o
        }

        private fun dispatchUpdate(args: Array<String>, subStart: Int, rootPath: String): Int {
            // takoyaki update [-r FILE|-] [--memory N] [--memory-reservation N]
            //   [--memory-swap N] [--cpu-quota N] [--cpu-period N]
            //   [--cpu-share N|--cpu-shares N] [--pids-limit N] [--cpuset-cpus S]
            //   [--cpu-burst N] [--cpu-idle N] <id>
            var resourcesPath: String? = null
            var memory: Long? = null
            var memoryReservation: Long? = null
            var memorySwap: Long? = null
            var cpuQuota: Long? = null
            var cpuPeriod: Long? = null
            var cpuShares: Long? = null
            var pidsLimit: Long? = null
            var cpusetCpus: String? = null
            var cpuBurst: Long? = null
            var cpuIdle: Long? = null
            var id: String? = null
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                when (a) {
                    "-r", "--resources" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        val rval = args[++i]
                        if (rval == "-") {
                            // Read resources JSON from stdin
                            resourcesPath = readStdinToTempFile() ?: return 1
                        } else {
                            resourcesPath = rval
                        }
                    }
                    "--memory" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        memory = parseMemoryValue("update", a, args[++i]) ?: return 1
                    }
                    "--memory-reservation" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        memoryReservation = parseMemoryValue("update", a, args[++i]) ?: return 1
                    }
                    "--memory-swap" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        memorySwap = parseMemoryValue("update", a, args[++i]) ?: return 1
                    }
                    "--cpu-quota" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        cpuQuota = parseLongOrFail("update", a, args[++i]) ?: return 1
                    }
                    "--cpu-period" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        cpuPeriod = parseLongOrFail("update", a, args[++i]) ?: return 1
                    }
                    "--cpu-share", "--cpu-shares" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        cpuShares = parseLongOrFail("update", a, args[++i]) ?: return 1
                    }
                    "--pids-limit" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        pidsLimit = parseLongOrFail("update", a, args[++i]) ?: return 1
                    }
                    "--cpuset-cpus" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        cpusetCpus = args[++i]
                    }
                    "--cpu-burst" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        cpuBurst = parseLongOrFail("update", a, args[++i]) ?: return 1
                    }
                    "--cpu-idle" -> {
                        if (i + 1 >= args.size) return missingArg("update", a)
                        cpuIdle = parseLongOrFail("update", a, args[++i]) ?: return 1
                    }
                    else -> {
                        if (a[0] != '-' && id == null) {
                            id = a
                        } else {
                            System.err.println("takoyaki update: unexpected arg: $a")
                            return 1
                        }
                    }
                }
                i++
            }
            if (id == null) {
                System.err.println("takoyaki update: missing container ID")
                return 1
            }
            return UpdateCommand.run(
                rootPath, id, resourcesPath, memory,
                memoryReservation, memorySwap, cpuQuota, cpuPeriod, cpuShares,
                pidsLimit, cpusetCpus, cpuBurst, cpuIdle
            )
        }

        /** Read stdin to a temp file and return its path. */
        private fun readStdinToTempFile(): String? {
            return try {
                val data = System.`in`.readAllBytes()
                val tmp = Files.createTempFile("takoyaki-update-", ".json")
                Files.write(tmp, data)
                tmp.toString()
            } catch (e: IOException) {
                System.err.println("failed to read stdin: ${e.message}")
                null
            }
        }

        /** Parse a memory value that may have units (K, M, G) or be a plain number. */
        private fun parseMemoryValue(sub: String, opt: String, value: String?): Long? {
            if (value.isNullOrEmpty()) return null
            // Check for -1 (unlimited)
            if (value == "-1") return -1L
            // Human-readable suffixes (case-insensitive)
            val upper = value.uppercase()
            var multiplier = 1L
            var numPart = value
            when {
                upper.endsWith("G") -> {
                    multiplier = 1024L * 1024 * 1024
                    numPart = value.dropLast(1)
                }
                upper.endsWith("M") -> {
                    multiplier = 1024L * 1024
                    numPart = value.dropLast(1)
                }
                upper.endsWith("K") -> {
                    multiplier = 1024L
                    numPart = value.dropLast(1)
                }
            }
            return numPart.toLongOrNull()?.let { it * multiplier }
                ?: run {
                    System.err.println("takoyaki $sub: $opt requires an integer, got: $value")
                    null
                }
        }

        private fun dispatchEvents(args: Array<String>, subStart: Int, rootPath: String): Int {
            // takoyaki events [--stats] [--interval DURATION] <id>
            var once = false
            var interval = "5s"
            var id: String? = null
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                when (a) {
                    "--stats" -> once = true
                    "--interval" -> {
                        if (i + 1 >= args.size) return missingArg("events", a)
                        interval = args[++i]
                    }
                    else -> {
                        if (a[0] != '-' && id == null) {
                            id = a
                        } else {
                            System.err.println("takoyaki events: unexpected arg: $a")
                            return 1
                        }
                    }
                }
                i++
            }
            if (id == null) {
                System.err.println("takoyaki events: missing container ID")
                return 1
            }
            return EventsCommand.run(rootPath, id, once, interval)
        }

        private fun dispatchExec(args: Array<String>, subStart: Int, rootPath: String): Int {
            // takoyaki exec [-p FILE] [-u UID[:GID]] [-t] [--cwd DIR] [-e KEY=VAL]...
            //               [--additional-gids GID]... [--preserve-fds N]
            //               [--cap CAP]... [--cgroup PATH] [--console-socket S]
            //               <id> [--] CMD [ARG...]
            var processJson: String? = null
            var user: String? = null
            var cwd: String? = null
            val envs = mutableListOf<String>()
            val additionalGids = mutableListOf<String>()
            val caps = mutableListOf<String>()
            var id: String? = null
            val command = mutableListOf<String>()
            var detach = false
            var tty = false
            var pidFile: String? = null
            var preserveFds = 0
            var consoleSocket: String? = null
            var cgroupPath: String? = null
            var consoleSizeStr: String? = null
            var pidfdSocket: String? = null
            var ignorePaused = false
            var afterPositional = false
            var i = subStart
            while (i < args.size) {
                val a = args[i]
                if (afterPositional) {
                    command.add(a)
                    i++
                    continue
                }
                if (a == "--") {
                    afterPositional = true
                    i++
                    continue
                }
                // Handle --flag=value form
                var flagKey = a
                var flagVal: String? = null
                val eqIdx = a.indexOf('=')
                if (eqIdx > 0 && a.startsWith("--")) {
                    flagKey = a.substring(0, eqIdx)
                    flagVal = a.substring(eqIdx + 1)
                }
                when (flagKey) {
                    "-p", "--process" -> {
                        if (flagVal != null) { processJson = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else processJson = args[++i]
                    }
                    "-u", "--user" -> {
                        if (flagVal != null) { user = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else user = args[++i]
                    }
                    "-d", "--detach" -> detach = true
                    "--pid-file" -> {
                        if (flagVal != null) { pidFile = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else pidFile = args[++i]
                    }
                    "--console-socket" -> {
                        if (flagVal != null) { consoleSocket = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else consoleSocket = args[++i]
                    }
                    "-t", "--tty" -> tty = true
                    "--cwd" -> {
                        if (flagVal != null) { cwd = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else cwd = args[++i]
                    }
                    "-e", "--env" -> {
                        if (flagVal != null) { envs.add(flagVal) }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else envs.add(args[++i])
                    }
                    "--additional-gids" -> {
                        if (flagVal != null) { additionalGids.add(flagVal) }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else additionalGids.add(args[++i])
                    }
                    "--preserve-fds" -> {
                        val vl = flagVal ?: if (i + 1 < args.size) args[++i] else null
                        if (vl == null) return missingArg("exec", a)
                        val v = parseIntOrFail("exec", "--preserve-fds", vl) ?: return 1
                        preserveFds = v
                    }
                    "--cap" -> {
                        if (flagVal != null) { caps.add(flagVal) }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else caps.add(args[++i])
                    }
                    "--cgroup" -> {
                        if (flagVal != null) { cgroupPath = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else cgroupPath = args[++i]
                    }
                    "--console-size" -> {
                        if (flagVal != null) { consoleSizeStr = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else consoleSizeStr = args[++i]
                    }
                    "--ignore-paused" -> ignorePaused = true
                    "--pidfd-socket" -> {
                        if (flagVal != null) { pidfdSocket = flagVal }
                        else if (i + 1 >= args.size) return missingArg("exec", a)
                        else pidfdSocket = args[++i]
                    }
                    "--no-new-privs" -> { /* accepted for compat, always-on in takoyaki */ }
                    "--apparmor", "--process-label" -> {
                        // Accept and skip these flags with their values
                        if (flagVal == null && i + 1 < args.size) i++
                    }
                    else -> {
                        if (a[0] != '-' && id == null) {
                            id = a
                            afterPositional = true // everything after = the command
                        } else {
                            System.err.println("takoyaki exec: unexpected arg: $a")
                            return 1
                        }
                    }
                }
                i++
            }
            if (id == null) {
                System.err.println("takoyaki exec: missing container ID")
                return 1
            }
            if (processJson == null && command.isEmpty()) {
                System.err.println("takoyaki exec: no command specified")
                return 1
            }
            // runc compat: --cgroup must not escape to parent (.. components).
            // "/" is allowed (means top-level cgroup, the default).
            val cgroup = cgroupPath
            if (cgroup != null && cgroup != "/") {
                if (".." in cgroup) {
                    System.err.println("bad sub cgroup path \"$cgroupPath\"")
                    return 1
                }
            }
            // Parse --console-size WIDTH:HEIGHT (runc uses WIDTH:HEIGHT order)
            var consoleSize: ConsoleSize? = null
            val sizeStr = consoleSizeStr
            if (sizeStr != null) {
                val parts = sizeStr.split(":")
                if (parts.size == 2) {
                    val w = parts[0].toIntOrNull()
                    val h = parts[1].toIntOrNull()
                    if (w == null || h == null) {
                        System.err.println("takoyaki exec: bad console-size: $consoleSizeStr")
                        return 1
                    }
                    consoleSize = ConsoleSize(width = w.toUInt(), height = h.toUInt())
                }
            }
            return ExecCommand.run(
                rootPath, id, processJson, user, cwd, envs, command,
                detach, pidFile, tty, consoleSocket, additionalGids, caps,
                preserveFds, cgroupPath, consoleSize, ignorePaused, pidfdSocket
            )
        }

        // ---- small helpers ------------------------------------------------

        private fun missingArg(sub: String, opt: String): Int {
            System.err.println("takoyaki $sub: $opt requires a value")
            return 1
        }

        private fun parseLongOrFail(sub: String, opt: String, value: String): Long? {
            return value.toLongOrNull()
                ?: run {
                    System.err.println("takoyaki $sub: $opt requires an integer, got: $value")
                    null
                }
        }

        // Int twin of parseLongOrFail. Kept separate because the historical int
        // sites print a shorter message (no ", got: <value>" suffix) and callers
        // depend on that exact output.
        private fun parseIntOrFail(sub: String, opt: String, value: String): Int? {
            return value.toIntOrNull()
                ?: run {
                    System.err.println("takoyaki $sub: $opt requires an integer")
                    null
                }
        }

        // ---- help text (runc-compatible format) ----------------------------

        /** Subcommand descriptions used for NAME: help blocks and for validating
         *  known subcommands. Includes runc subcommands that takoyaki does not
         *  implement (checkpoint, restore, features) so that `runc <sub> -h`
         *  still prints a NAME: block instead of "No help topic". */
        private val SUBCOMMAND_DESCRIPTIONS: Map<String, String> = mapOf(
            "create" to "create a container",
            "run" to "create and run a container",
            "start" to "start a created container",
            "state" to "output the state of a container",
            "kill" to "send a signal to a container",
            "delete" to "delete any resources held by the container",
            "list" to "lists containers",
            "ls" to "lists containers",
            "ps" to "ps displays the processes running inside a container",
            "pause" to "pause suspends all processes inside the container",
            "resume" to "resumes all processes that have been previously paused",
            "update" to "update container resource constraints",
            "events" to "display container events such as OOM notifications and stats",
            "exec" to "execute new process inside the container",
            "spec" to "create a new specification file",
            "checkpoint" to "checkpoint a running container",
            "restore" to "restore a container from a previous checkpoint",
            "features" to "show the enabled features"
        )

        private fun printVersion() {
            println("runc version $VERSION")
            println("commit: (none)")
            println("spec: $OCI_SPEC_VERSION")
        }

        private fun printRootHelp() {
            // runc-compatible NAME:/USAGE: format so bats tests match.
            println("""
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
                   --version, -v       print the version""".trimIndent())
        }

        private fun printSubcommandHelp(sub: String) {
            val desc = SUBCOMMAND_DESCRIPTIONS[sub] ?: sub
            println("NAME:")
            println("   runc $sub - $desc")
        }
    }
}

fun main(args: Array<String>) {
    Main.main(args)
}
