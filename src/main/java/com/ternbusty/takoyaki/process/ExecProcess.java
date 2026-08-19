package com.ternbusty.takoyaki.process;

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

        int payloadFd;
        int seccompListenerFd;
        try {
            payloadFd = Integer.parseInt(System.getenv("_TAKOYAKI_EXEC_PAYLOAD_FD"));
            String listenerFdStr = System.getenv("_TAKOYAKI_SECCOMP_LISTENER_FD");
            seccompListenerFd = listenerFdStr != null ? Integer.parseInt(listenerFdStr) : -1;
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

        try (Arena arena = Arena.ofConfined()) {
            // oom_score_adj first, while still privileged; inherited across execve.
            ProcessRestrictions.applyOomScoreAdj(payload.process.oomScoreAdj);

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
            String homeVal = envMap.get("HOME");
            if (homeVal == null || homeVal.isEmpty()) {
                int uid = payload.process.user != null ? payload.process.user.uid : 0;
                String passwdHome = com.ternbusty.takoyaki.rootfs.UserDb.lookupHome(uid);
                if (passwdHome != null && !passwdHome.isEmpty()) {
                    envMap.put("HOME", passwdHome);
                } else if (homeVal == null) {
                    envMap.put("HOME", uid == 0 ? "/root" : "/");
                }
            }

            Libc.clearenv();
            for (var envEntry : envMap.entrySet()) {
                Libc.setenv(arena, envEntry.getKey(), envEntry.getValue(), true);
            }

            // Flag every inherited runtime fd CLOEXEC so nothing leaks into the
            // user process (the payload fd is closed; the seccomp listener fd
            // has been forwarded by Seccomp.apply if it was needed).
            CloseRange.closeAllAbove(0);

            String[] argv = payload.process.args.toArray(new String[0]);

            // Rlimits dead-last: a low RLIMIT_AS applied any earlier could push
            // the already-mapped SubstrateVM heap over the limit and abort us
            // before execve. The user process picks the limits up across exec.
            if (payload.process.rlimits != null) {
                com.ternbusty.takoyaki.syscall.Rlimit.apply(Libc.getpid(),
                        payload.process.rlimits);
            }

            Libc.execvp(arena, argv[0], argv);
            String errMsg = Libc.strerror(Libc.errno());
            System.err.println("exec " + argv[0] + ": " + errMsg);
            Logger.error("execvp failed: " + errMsg);
        } catch (Exception e) {
            Logger.error("exec setup failed: " + e.getMessage());
        }
        PosixIO._exit(127);
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
