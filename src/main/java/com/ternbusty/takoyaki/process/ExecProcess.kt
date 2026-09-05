package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.ipc.SyncChannel
import com.ternbusty.takoyaki.keyring.Keyring
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.selinux.SeLinux
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.CloseRange
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.util.JsonCodec
import java.io.ByteArrayOutputStream
import java.lang.foreign.Arena

/**
 * The in-container half of `takoyaki exec`, entered via re-exec of
 * `/proc/self/exe __exec__` -- the exact structure of the create path
 * (bootstrap.c stage machinery) and of runc's nsexec.
 *
 * The re-exec happens while still in the host namespaces: the binary is
 * dynamically linked against libc.so.6 / libseccomp.so.2 (--static-nolibc
 * build), so an execve after joining the container mount namespace would have
 * ld.so resolve the interpreter and libraries inside the container rootfs --
 * which doesn't have them on musl / distroless images.
 *
 * By the time Java runs here, bootstrap.c's exec_bootstrap has already joined
 * every container namespace and clone'd THIS process inside them (see
 * bootstrap.c for why both the pre-thread setns and the post-setns clone are
 * load-bearing), reported our pid to the CLI, and exited its intermediate.
 * We are a direct child of the CLI (CLONE_PARENT), which waitpid's us for the
 * exit code. Container cgroup membership was arranged by the CLI, which wrote
 * our pid to cgroup.procs before sending the payload -- reading the payload to
 * EOF is therefore also the sync point that guarantees membership before any
 * user code runs.
 *
 * Sequence: read the payload, apply the shared restriction sequence, and
 * execve the user command in place. No further fork -- this process IS the
 * workload, so its ancestors exiting (detached exec) reparents it straight to
 * the caller's subreaper, which is how containerd's shim observes its exit.
 */
object ExecProcess {

    fun run() {
        Logger.context = "exec"
        // Inherit log file/format from the CLI so debug output goes to --log
        // rather than leaking to stderr (same pattern as InitProcess).
        System.getenv("_TAKOYAKI_LOG_FILE")?.let { Logger.setLogFile(it) }
        val execLogFormat = System.getenv("_TAKOYAKI_LOG_FORMAT")
        if ("json".equals(execLogFormat, ignoreCase = true)) {
            Logger.format = Logger.Format.JSON
        }

        val payloadFd: Int
        val seccompListenerFd: Int
        var consoleFd: Int
        val execSyncFd: Int
        try {
            payloadFd = System.getenv("_TAKOYAKI_EXEC_PAYLOAD_FD").toInt()
            seccompListenerFd = System.getenv("_TAKOYAKI_SECCOMP_LISTENER_FD")?.toInt() ?: -1
            consoleFd = System.getenv("_TAKOYAKI_EXEC_CONSOLE_FD")?.toInt() ?: -1
            execSyncFd = System.getenv("_TAKOYAKI_EXEC_SYNC_FD")?.toInt() ?: -1
        } catch (e: RuntimeException) {
            Logger.error("bad exec env vars: ${e.message}")
            PosixIO._exit(1)
            return
        }

        val payload: ExecPayload?
        try {
            payload = JsonCodec.decode<ExecPayload>(readToEof(payloadFd))
        } catch (e: Exception) {
            Logger.error("failed to read exec payload: ${e.message}")
            PosixIO._exit(1)
            return
        }
        val proc = payload?.process
        if (payload == null || proc == null || proc.args.isNullOrEmpty()) {
            Logger.error("exec payload has no process.args")
            PosixIO._exit(1)
            return
        }
        PosixIO.close(payloadFd)

        // Enter the container's cgroup namespace NOW, after reading the payload.
        // The payload read blocks until the CLI finishes Cgroup.addPid (which
        // writes our pid to the container's cgroup.procs), so by this point we
        // are a member of the container's cgroup. Entering cgroupns here makes
        // /proc/self/cgroup correctly show "0::/" instead of a host-relative path.
        // The fd was opened by ExecCommand and deliberately kept out of
        // bootstrap.c's setns loop for this reason.
        System.getenv("_TAKOYAKI_EXEC_CGROUPNS_FD")?.let { cgroupNsFdStr ->
            val cgroupNsFd = cgroupNsFdStr.toInt()
            if (Libc.setns(cgroupNsFd, Constants.CLONE_NEWCGROUP) != 0) {
                Logger.warn("setns(cgroupns) failed: ${Libc.strerror(Libc.errno())}")
            } else {
                Logger.debug("entered container cgroup namespace")
            }
            PosixIO.close(cgroupNsFd)
        }

        try {
            Arena.ofConfined().use { arena ->
                // oom_score_adj first, while still privileged; inherited across execve.
                ProcessRestrictions.applyOomScoreAdj(proc.oomScoreAdj)

                // I/O priority and scheduler before the restriction sequence.
                ProcessRestrictions.applyIOPriority(proc.ioPriority)
                ProcessRestrictions.applyScheduler(proc.scheduler)

                // NUMA memory policy inherited from the container's linux config.
                MemPolicy.apply(payload.memoryPolicy)

                // Apply rlimits BEFORE dropping capabilities (ProcessRestrictions.apply).
                // Setting RLIMIT_NOFILE above fs.nr_open requires CAP_SYS_RESOURCE,
                // which is gone after cap drop. RLIMIT_AS is deferred to just before
                // execve to avoid OOMing the JVM's heap. Same order as InitProcess.
                if (proc.rlimits != null) {
                    com.ternbusty.takoyaki.syscall.Rlimit.applyExcept(
                        Libc.getpid(), proc.rlimits, "RLIMIT_AS"
                    )
                }

                // Join the container's session keyring unless --no-new-keyring was
                // used at creation time.  The init process created a named session
                // keyring "_ses.<id>"; exec joins it so child processes share the
                // same keyring. When a SELinux label is configured, set keycreate
                // before the join so the kernel stamps the correct label on any
                // key that gets created (same pattern as InitProcess).
                if (!payload.noNewKeyring) {
                    val seLabel = proc.selinuxLabel
                    SeLinux.applyKeyCreate(seLabel)
                    Keyring.joinNewSession("_ses.${payload.containerId}")
                    SeLinux.clearKeyCreate()
                }

                // getpid() is the pid inside the container's pid ns -- the same
                // perspective the init path reports to a SCMP_ACT_NOTIFY listener,
                // and the pid the seccomp filter actually applies to.
                val listenerState = State.create(
                    payload.ociVersion ?: "", payload.containerId ?: "",
                    ContainerStatus.RUNNING, Libc.getpid(), payload.bundle ?: "", null
                )

                ProcessRestrictions.apply(
                    proc, payload.seccomp,
                    listenerState, seccompListenerFd
                )

                val cwd = proc.cwd ?: "/"
                if (Libc.chdir(arena, cwd) != 0) {
                    Logger.warn("chdir $cwd failed: ${Libc.strerror(Libc.errno())}")
                }

                // Prepare the environment: dedup (last wins), inject HOME if empty.
                val envMap = LinkedHashMap<String, String>()
                proc.env?.forEach { entry ->
                    val eq = entry.indexOf('=')
                    if (eq > 0) {
                        envMap[entry.substring(0, eq)] = entry.substring(eq + 1)
                    }
                }
                // runc behaviour (env.go prepareEnv): if HOME is empty or absent
                // after dedup, look up the user's home in /etc/passwd and set it.
                // Non-empty HOME is kept as-is.
                val homeVal = envMap["HOME"]
                if (homeVal.isNullOrEmpty()) {
                    val uid = proc.user?.uid ?: 0u
                    val passwdHome = com.ternbusty.takoyaki.rootfs.UserDb.lookupHome(uid.toInt())
                    if (!passwdHome.isNullOrEmpty()) {
                        envMap["HOME"] = passwdHome
                    } else {
                        // /etc/passwd has no entry: default to "/" (runc's getUserHome default).
                        envMap["HOME"] = "/"
                    }
                }

                Libc.clearenv()
                for ((key, value) in envMap) {
                    Libc.setenv(arena, key, value, true)
                }

                // PTY setup for exec -t: allocate a pty from the container's devpts,
                // ship the master back to ExecCommand via the console socketpair,
                // and wire the slave to stdin/stdout/stderr.
                if (proc.terminal == true && consoleFd >= 0) {
                    val pty = com.ternbusty.takoyaki.console.ConsoleSocket.openPty()
                    if (pty != null) {
                        if (com.ternbusty.takoyaki.console.ConsoleSocket
                                .sendMasterVia(consoleFd, pty.master)
                        ) {
                            val cs = proc.consoleSize
                        if (cs != null) {
                                com.ternbusty.takoyaki.console.ConsoleSocket.setWinsize(
                                    pty.slave,
                                    cs.height.toInt(),
                                    cs.width.toInt()
                                )
                            }
                            com.ternbusty.takoyaki.console.ConsoleSocket.wireStdio(pty.slave)
                        }
                        PosixIO.close(pty.master)
                    }
                    PosixIO.close(consoleFd)
                    consoleFd = -1
                }
                if (consoleFd >= 0) PosixIO.close(consoleFd)

                // Signal ExecCommand that all process restrictions have been applied.
                // ExecCommand waits for this byte before writing the pid file, so
                // the scheduler / capabilities / seccomp are guaranteed to be in
                // place before any external observer can inspect the process.
                if (execSyncFd >= 0) {
                    SyncChannel.writeByte(execSyncFd, 0.toByte())
                    PosixIO.close(execSyncFd)
                }

                // Flag every inherited runtime fd CLOEXEC so nothing leaks into the
                // user process (the seccomp listener fd has been forwarded by
                // Seccomp.apply if it was needed).
                CloseRange.closeAllAbove(payload.preserveFds)

                val argv = proc.args.toTypedArray()

                // RLIMIT_AS dead-last: a low RLIMIT_AS applied any earlier could push
                // the already-mapped SubstrateVM heap over the limit and abort us
                // before execve. Other rlimits were already applied above (before
                // cap drop). Same deferred pattern as InitProcess.
                if (proc.rlimits != null) {
                    com.ternbusty.takoyaki.syscall.Rlimit.applyOnly(
                        Libc.getpid(), proc.rlimits, "RLIMIT_AS"
                    )
                }

                Logger.debug("setns_init: about to exec")
                // Re-apply CLOEXEC right before exec to catch FDs opened by
                // rlimit or other code since the first closeAllAbove.
                CloseRange.closeAllAbove(payload.preserveFds)
                Libc.execvp(arena, argv[0], argv)
                val rawErr = Libc.strerror(Libc.errno())
                val errMsg = if (rawErr.isEmpty()) rawErr
                else rawErr[0].lowercaseChar() + rawErr.substring(1)
                System.err.println("exec ${argv[0]}: $errMsg")
                Logger.error("execvp failed: $errMsg")
            }
        } catch (e: Exception) {
            Logger.error("exec setup failed: ${e.message}")
        }
        PosixIO._exit(255)
    }

    /** Read fd to EOF (retrying EINTR) and return the content as a string. */
    private fun readToEof(fd: Int): String {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        Arena.ofConfined().use { arena ->
            while (true) {
                val n = PosixIO.read(arena, fd, buf)
                if (n > 0) {
                    out.write(buf, 0, n.toInt())
                } else if (n == 0L) {
                    break
                } else if (Libc.errno() != Constants.EINTR) {
                    throw RuntimeException("read: ${Libc.strerror(Libc.errno())}")
                }
            }
        }
        return out.toString()
    }
}
