package com.ternbusty.takoyaki.process;

import com.ternbusty.takoyaki.ipc.SyncChannel;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.CloseRange;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.util.Json;

import java.io.ByteArrayOutputStream;
import java.lang.foreign.Arena;

/**
 * The in-container half of `takoyaki exec`, entered via re-exec of
 * {@code /proc/self/exe __exec__} — the exact structure of the create path
 * (bootstrap.c stage machinery) and of runc's nsexec.
 *
 * The re-exec happens while still in the host namespaces: the binary is
 * dynamically linked against libc.so.6 / libseccomp.so.2 (--static-nolibc
 * build), so an execve after joining the container mount namespace would have
 * ld.so resolve the interpreter and libraries inside the container rootfs —
 * which doesn't have them on musl / distroless images.
 *
 * By the time Java runs here, bootstrap.c's exec_bootstrap has already joined
 * every container namespace and clone'd THIS process inside them (see
 * bootstrap.c for why both the pre-thread setns and the post-setns clone are
 * load-bearing), reported our pid to the CLI, and exited its intermediate.
 * We are a direct child of the CLI (CLONE_PARENT), which waitpid's us for the
 * exit code. Container cgroup membership was arranged by the CLI, which wrote
 * our pid to cgroup.procs before sending the payload — reading the payload to
 * EOF is therefore also the sync point that guarantees membership before any
 * user code runs.
 *
 * Sequence: read the payload, apply the shared restriction sequence, and
 * execve the user command in place. No further fork — this process IS the
 * workload, so its ancestors exiting (detached exec) reparents it straight to
 * the caller's subreaper, which is how containerd's shim observes its exit.
 */
public final class ExecProcess {
    private ExecProcess() {}

    public static void run() {
        Logger.setContext("exec");
        // Inherit log file/format from the CLI so debug output goes to --log
        // rather than leaking to stderr (same pattern as InitProcess).
        String execLogFile = System.getenv("_TAKOYAKI_LOG_FILE");
        if (execLogFile != null) {
            Logger.setLogFile(execLogFile);
        }
        String execLogFormat = System.getenv("_TAKOYAKI_LOG_FORMAT");
        if ("json".equalsIgnoreCase(execLogFormat)) {
            Logger.setFormat(Logger.Format.JSON);
        }

        int payloadFd;
        int seccompListenerFd;
        int consoleFd;
        int execSyncFd;
        try {
            payloadFd = Integer.parseInt(System.getenv("_TAKOYAKI_EXEC_PAYLOAD_FD"));
            String listenerFdStr = System.getenv("_TAKOYAKI_SECCOMP_LISTENER_FD");
            seccompListenerFd = listenerFdStr != null ? Integer.parseInt(listenerFdStr) : -1;
            String consoleFdStr = System.getenv("_TAKOYAKI_EXEC_CONSOLE_FD");
            consoleFd = consoleFdStr != null ? Integer.parseInt(consoleFdStr) : -1;
            String syncFdStr = System.getenv("_TAKOYAKI_EXEC_SYNC_FD");
            execSyncFd = syncFdStr != null ? Integer.parseInt(syncFdStr) : -1;
        } catch (RuntimeException e) {
            Logger.error("bad exec env vars: " + e.getMessage());
            PosixIO._exit(1);
            return;
        }

        ExecPayload payload;
        try {
            payload = Json.decode(readToEof(payloadFd), ExecPayload::fromJson);
        } catch (Exception e) {
            Logger.error("failed to read exec payload: " + e.getMessage());
            PosixIO._exit(1);
            return;
        }
        if (payload == null || payload.process == null || payload.process.args == null
                || payload.process.args.isEmpty()) {
            Logger.error("exec payload has no process.args");
            PosixIO._exit(1);
            return;
        }
        PosixIO.close(payloadFd);

        // Enter the container's cgroup namespace NOW, after reading the payload.
        // The payload read blocks until the CLI finishes Cgroup.addPid (which
        // writes our pid to the container's cgroup.procs), so by this point we
        // are a member of the container's cgroup. Entering cgroupns here makes
        // /proc/self/cgroup correctly show "0::/" instead of a host-relative path.
        // The fd was opened by ExecCommand and deliberately kept out of
        // bootstrap.c's setns loop for this reason.
        String cgroupNsFdStr = System.getenv("_TAKOYAKI_EXEC_CGROUPNS_FD");
        if (cgroupNsFdStr != null) {
            int cgroupNsFd = Integer.parseInt(cgroupNsFdStr);
            if (Libc.setns(cgroupNsFd, Constants.CLONE_NEWCGROUP) != 0) {
                Logger.warn("setns(cgroupns) failed: " + Libc.strerror(Libc.errno()));
            } else {
                Logger.debug("entered container cgroup namespace");
            }
            PosixIO.close(cgroupNsFd);
        }

        try (Arena arena = Arena.ofConfined()) {
            // oom_score_adj first, while still privileged; inherited across execve.
            ProcessRestrictions.applyOomScoreAdj(payload.process.oomScoreAdj);

            // I/O priority and scheduler before the restriction sequence.
            ProcessRestrictions.applyIOPriority(payload.process.ioPriority);
            ProcessRestrictions.applyScheduler(payload.process.scheduler);

            // Apply rlimits BEFORE dropping capabilities (ProcessRestrictions.apply).
            // Setting RLIMIT_NOFILE above fs.nr_open requires CAP_SYS_RESOURCE,
            // which is gone after cap drop. RLIMIT_AS is deferred to just before
            // execve to avoid OOMing the JVM's heap. Same order as InitProcess.
            if (payload.process.rlimits != null) {
                com.ternbusty.takoyaki.syscall.Rlimit.applyExcept(
                        Libc.getpid(), payload.process.rlimits, "RLIMIT_AS");
            }

            // getpid() is the pid inside the container's pid ns — the same
            // perspective the init path reports to a SCMP_ACT_NOTIFY listener,
            // and the pid the seccomp filter actually applies to.
            State listenerState = State.create(payload.ociVersion, payload.containerId,
                    ContainerStatus.RUNNING, Libc.getpid(), payload.bundle, null);

            ProcessRestrictions.apply(payload.process, payload.seccomp,
                    listenerState, seccompListenerFd);

            String cwd = payload.process.cwd != null ? payload.process.cwd : "/";
            if (Libc.chdir(arena, cwd) != 0) {
                Logger.warn("chdir " + cwd + " failed: " + Libc.strerror(Libc.errno()));
            }

            // Prepare the environment: dedup (last wins), inject HOME if empty.
            java.util.LinkedHashMap<String, String> envMap = new java.util.LinkedHashMap<>();
            if (payload.process.env != null) {
                for (String entry : payload.process.env) {
                    int eq = entry.indexOf('=');
                    if (eq > 0) {
                        envMap.put(entry.substring(0, eq), entry.substring(eq + 1));
                    }
                }
            }
            // runc behaviour (env.go prepareEnv): if HOME is empty or absent
            // after dedup, look up the user's home in /etc/passwd and set it.
            // Non-empty HOME is kept as-is.
            String homeVal = envMap.get("HOME");
            if (homeVal == null || homeVal.isEmpty()) {
                int uid = payload.process.user != null ? payload.process.user.uid : 0;
                String passwdHome = com.ternbusty.takoyaki.rootfs.UserDb.lookupHome(uid);
                if (passwdHome != null && !passwdHome.isEmpty()) {
                    envMap.put("HOME", passwdHome);
                } else {
                    // /etc/passwd has no entry: default to "/" (runc's getUserHome default).
                    envMap.put("HOME", "/");
                }
            }

            Libc.clearenv();
            for (var envEntry : envMap.entrySet()) {
                Libc.setenv(arena, envEntry.getKey(), envEntry.getValue(), true);
            }

            // PTY setup for exec -t: allocate a pty from the container's devpts,
            // ship the master back to ExecCommand via the console socketpair,
            // and wire the slave to stdin/stdout/stderr.
            if (Boolean.TRUE.equals(payload.process.terminal) && consoleFd >= 0) {
                com.ternbusty.takoyaki.console.ConsoleSocket.PtyPair pty =
                        com.ternbusty.takoyaki.console.ConsoleSocket.openPty();
                if (pty != null) {
                    if (com.ternbusty.takoyaki.console.ConsoleSocket
                            .sendMasterVia(consoleFd, pty.master)) {
                        if (payload.process.consoleSize != null) {
                            com.ternbusty.takoyaki.console.ConsoleSocket.setWinsize(
                                    pty.slave,
                                    payload.process.consoleSize.height,
                                    payload.process.consoleSize.width);
                        }
                        com.ternbusty.takoyaki.console.ConsoleSocket.wireStdio(pty.slave);
                    }
                    PosixIO.close(pty.master);
                }
                PosixIO.close(consoleFd);
                consoleFd = -1;
            }
            if (consoleFd >= 0) PosixIO.close(consoleFd);

            // Signal ExecCommand that all process restrictions have been applied.
            // ExecCommand waits for this byte before writing the pid file, so
            // the scheduler / capabilities / seccomp are guaranteed to be in
            // place before any external observer can inspect the process.
            if (execSyncFd >= 0) {
                SyncChannel.writeByte(execSyncFd, (byte) 0);
                PosixIO.close(execSyncFd);
            }

            // Flag every inherited runtime fd CLOEXEC so nothing leaks into the
            // user process (the seccomp listener fd has been forwarded by
            // Seccomp.apply if it was needed).
            CloseRange.closeAllAbove(payload.preserveFds);

            String[] argv = payload.process.args.toArray(new String[0]);

            // RLIMIT_AS dead-last: a low RLIMIT_AS applied any earlier could push
            // the already-mapped SubstrateVM heap over the limit and abort us
            // before execve. Other rlimits were already applied above (before
            // cap drop). Same deferred pattern as InitProcess.
            if (payload.process.rlimits != null) {
                com.ternbusty.takoyaki.syscall.Rlimit.applyOnly(Libc.getpid(),
                        payload.process.rlimits, "RLIMIT_AS");
            }

            Logger.debug("setns_init: about to exec");
            // Re-apply CLOEXEC right before exec to catch FDs opened by
            // rlimit or other code since the first closeAllAbove.
            CloseRange.closeAllAbove(payload.preserveFds);
            Libc.execvp(arena, argv[0], argv);
            String rawErr = Libc.strerror(Libc.errno());
            String errMsg = rawErr.isEmpty() ? rawErr
                    : Character.toLowerCase(rawErr.charAt(0)) + rawErr.substring(1);
            System.err.println("exec " + argv[0] + ": " + errMsg);
            Logger.error("execvp failed: " + errMsg);
        } catch (Exception e) {
            Logger.error("exec setup failed: " + e.getMessage());
        }
        PosixIO._exit(255);
    }

    /** Read fd to EOF (retrying EINTR) and return the content as a string. */
    private static String readToEof(int fd) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        try (Arena arena = Arena.ofConfined()) {
            while (true) {
                long n = PosixIO.read(arena, fd, buf);
                if (n > 0) {
                    out.write(buf, 0, (int) n);
                } else if (n == 0) {
                    break;
                } else if (Libc.errno() != Constants.EINTR) {
                    throw new RuntimeException("read: " + Libc.strerror(Libc.errno()));
                }
            }
        }
        return out.toString();
    }
}
