package com.ternbusty.takoyaki.process;

import com.ternbusty.takoyaki.apparmor.AppArmor;
import com.ternbusty.takoyaki.capability.Capability;
import com.ternbusty.takoyaki.console.ConsoleSocket;
import com.ternbusty.takoyaki.ipc.NotifySocket;
import com.ternbusty.takoyaki.ipc.SyncChannel;
import com.ternbusty.takoyaki.keyring.Keyring;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.network.Loopback;
import com.ternbusty.takoyaki.rootfs.Devices;
import com.ternbusty.takoyaki.rootfs.Rootfs;
import com.ternbusty.takoyaki.rootfs.UserDb;
import com.ternbusty.takoyaki.seccomp.Seccomp;
import com.ternbusty.takoyaki.selinux.SeLinux;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.CloseRange;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Groups;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.sysctl.Sysctl;
import com.ternbusty.takoyaki.time.TimeNs;
import com.ternbusty.takoyaki.util.Json;

import java.lang.foreign.Arena;
import java.nio.file.Files;
import java.nio.file.Path;

public final class InitProcess {
    private InitProcess() {}

    /**
     * Parse the {@code _TAKOYAKI_IDMAP_FDS} env value into a destination-path
     * -> fd map.
     *
     * Wire format: {@code base64(destPath1):fd1,base64(destPath2):fd2,...}
     * Base64 because destination paths can contain '=' or ',' which are the
     * separators. Malformed entries (missing colon, bogus base64) are silently
     * skipped — the init must still come up.
     *
     * Package-visible for unit tests.
     */
    static java.util.Map<String, Integer> parseIdmapFds(String env) {
        java.util.Map<String, Integer> out = new java.util.LinkedHashMap<>();
        if (env == null || env.isEmpty()) return out;
        for (String entry : env.split(",")) {
            int colon = entry.indexOf(':');
            if (colon < 0) continue;
            try {
                String dest = new String(java.util.Base64.getDecoder()
                        .decode(entry.substring(0, colon)));
                int fd = Integer.parseInt(entry.substring(colon + 1));
                out.put(dest, fd);
            } catch (IllegalArgumentException ignored) {
                // bad base64 or non-numeric fd; skip
            }
        }
        return out;
    }

    public static void run() {
        Logger.setContext("init");
        Logger.debug("init started, pid=" + Libc.getpid() + " ppid=" + Libc.getppid());
        try {
            String mntNs = Files.readSymbolicLink(Path.of("/proc/self/ns/mnt")).toString();
            String pidNs = Files.readSymbolicLink(Path.of("/proc/self/ns/pid")).toString();
            Logger.debug("init mnt_ns=" + mntNs + " pid_ns=" + pidNs);
        } catch (Exception e) {
            Logger.warn("could not read ns: " + e.getMessage());
        }

        String bundlePath = System.getenv("_TAKOYAKI_BUNDLE_PATH");
        String rootfsPath = System.getenv("_TAKOYAKI_ROOTFS_PATH");
        String mainSenderFdStr = System.getenv("_TAKOYAKI_MAIN_SENDER_FD");
        String notifyListenerFdStr = System.getenv("_TAKOYAKI_NOTIFY_LISTENER_FD");

        if (bundlePath == null || rootfsPath == null || mainSenderFdStr == null
                || notifyListenerFdStr == null) {
            Logger.error("missing required env vars");
            PosixIO._exit(1);
            return;
        }

        int mainSenderFd = Integer.parseInt(mainSenderFdStr);
        int notifyListenerFd = Integer.parseInt(notifyListenerFdStr);

        Spec spec;
        try {
            spec = Json.readFile(Path.of(bundlePath, "config.json"), Spec::fromJson);
        } catch (Exception e) {
            Logger.error("failed to load spec: " + e.getMessage());
            PosixIO._exit(1);
            return;
        }

        try (Arena arena = Arena.ofConfined()) {
            // libseccomp.so.2 is linked at NEEDED so ld.so loads it at process startup,
            // before pivot_root replaces the rootfs. No explicit preload required.

            // Become subreaper so orphaned descendants are reaped by this init
            // (PID 1 inside the container's pid namespace).
            if (Libc.prctl(Constants.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
                Logger.debug("PR_SET_CHILD_SUBREAPER failed: " + Libc.strerror(Libc.errno()));
            }

            // timens offsets are applied in bootstrap.c stage-1 (before execve into
            // the Java init), because /proc/self/timens_offsets is no longer writable
            // after exec or after gettimeofday is called. The Java init cannot do it.

            // Apply process.oomScoreAdj. Writes to /proc/self/oom_score_adj so it
            // is inherited by the user process after exec.
            if (spec.process != null && spec.process.oomScoreAdj != null) {
                try {
                    java.nio.file.Files.writeString(
                            java.nio.file.Path.of("/proc/self/oom_score_adj"),
                            spec.process.oomScoreAdj.toString());
                    Logger.debug("oom_score_adj=" + spec.process.oomScoreAdj);
                } catch (java.io.IOException e) {
                    Logger.warn("write oom_score_adj failed: " + e.getMessage());
                }
            }

            // Parse pre-prepared idmap helper fds passed via env from CreateCommand.
            // Keys are base64-encoded destination paths; values are fd numbers
            // referring to /proc/<helper>/ns/user opened in the host pid/user ns,
            // inherited across fork+execve.
            java.util.Map<String, Integer> idmapFds =
                    parseIdmapFds(System.getenv("_TAKOYAKI_IDMAP_FDS"));
            for (var e : idmapFds.entrySet()) {
                Logger.debug("idmap fd inherited: " + e.getKey() + " -> " + e.getValue());
            }

            if (spec.hasNamespace("mount")) {
                Rootfs.prepare(rootfsPath, spec, idmapFds);
                // Additional devices declared in spec.linux.devices, before pivot_root.
                if (spec.linux != null && spec.linux.devices != null) {
                    Devices.create(rootfsPath, spec.linux.devices);
                }
                Rootfs.pivot(rootfsPath,
                        spec.linux != null ? spec.linux.rootfsPropagation : null);
            } else {
                Logger.debug("no mount namespace, skipping rootfs prep");
            }

            // Bring up loopback so localhost works inside the network namespace.
            if (spec.hasNamespace("network")) {
                Loopback.up();
            }

            // Apply spec.linux.sysctl after mounts are in place (so /proc/sys is visible).
            if (spec.linux != null && spec.linux.sysctl != null) {
                Sysctl.apply(spec.linux.sysctl);
            }

            String cwd = spec.process != null && spec.process.cwd != null ? spec.process.cwd : "/";
            if (Libc.chdir(arena, cwd) != 0) {
                Logger.warn("chdir " + cwd + " failed: " + Libc.strerror(Libc.errno()));
            }

            if (spec.hostname != null) {
                if (Libc.sethostname(arena, spec.hostname) != 0) {
                    Logger.warn("sethostname failed: " + Libc.strerror(Libc.errno()));
                } else {
                    Logger.debug("hostname set to " + spec.hostname);
                }
            }

            // Mask sensitive paths and remount others read-only BEFORE the root is made RO,
            // so the bind / remount itself can still succeed.
            if (spec.linux != null) {
                Rootfs.maskPaths(spec.linux.maskedPaths);
                Rootfs.readonlyRemount(spec.linux.readonlyPaths);
            }

            // Generate /etc/passwd and /etc/group entries while still writable.
            if (spec.process != null) {
                UserDb.ensure(spec.process.user,
                        spec.process.user == null ? null : spec.process.user.additionalGids);
            }

            if (spec.root != null && spec.root.readonly) {
                Rootfs.setRootReadonly();
            }

            if (spec.process != null && spec.process.umask != null) {
                Libc.umask(spec.process.umask.intValue());
            }

            // Order rationale (matches runc / youki):
            //
            //   1. AppArmor / SELinux label staging
            //   2. PR_SET_NO_NEW_PRIVS (only if spec asks)
            //   3. seccomp_load — done HERE (still with full caps inherited from
            //      bootstrap) so seccomp(2) doesn't fail with EACCES. With
            //      libseccomp's auto-NNP disabled (SCMP_FLTATR_CTL_NNP=0),
            //      seccomp(2) needs either CAP_SYS_ADMIN OR a pre-set NNP.
            //      After capability drop + setuid, a typical container has
            //      neither, so a spec with noNewPrivileges=false plus a
            //      non-empty seccomp profile would fail to load. Doing it
            //      here while we still hold CAP_SYS_ADMIN avoids that.
            //   4. Capability bounding set / keep_caps
            //   5. setgroups / setresgid / setresuid
            //   6. capset (final effective/permitted/inheritable/ambient)
            //   7. PR_SET_DUMPABLE=0
            //   8. execve into user process

            if (spec.process != null && spec.process.apparmorProfile != null) {
                AppArmor.apply(spec.process.apparmorProfile);
            }
            if (spec.process != null && spec.process.selinuxLabel != null) {
                SeLinux.apply(spec.process.selinuxLabel);
            }

            if (Boolean.TRUE.equals(spec.process != null ? spec.process.noNewPrivileges : null)) {
                if (Libc.prctl(Constants.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                    Logger.warn("PR_SET_NO_NEW_PRIVS failed");
                } else {
                    Logger.debug("no_new_privileges set");
                }
            }

            // Join a fresh kernel session keyring unless the caller opted out via
            // --no-new-keyring (we propagate that via env var).
            if (!"1".equals(System.getenv("_TAKOYAKI_NO_NEW_KEYRING"))) {
                Keyring.joinNewSession("takoyaki-" + Libc.getpid());
            }

            if (spec.linux != null && spec.linux.seccomp != null) {
                Seccomp.apply(spec.linux.seccomp,
                        System.getenv("_TAKOYAKI_CONTAINER_ID"), bundlePath);
            }

            Spec.LinuxCapabilities caps = spec.process != null ? spec.process.capabilities : null;
            if (caps != null) {
                Capability.applyBoundingSet(caps);
                Capability.setKeepCaps();
            }

            if (spec.process != null && spec.process.user != null
                    && spec.process.user.additionalGids != null) {
                Groups.setAdditional(spec.process.user.additionalGids);
            }

            int targetGid = spec.process != null && spec.process.user != null ? spec.process.user.gid : 0;
            int targetUid = spec.process != null && spec.process.user != null ? spec.process.user.uid : 0;
            // setresgid/setresuid drops real/effective/saved IDs all at once so the
            // process can't restore privileges via saved UID.
            if (Libc.setresgid(targetGid, targetGid, targetGid) != 0) {
                Logger.warn("setresgid " + targetGid + " failed: " + Libc.strerror(Libc.errno()));
            }
            if (Libc.setresuid(targetUid, targetUid, targetUid) != 0) {
                Logger.warn("setresuid " + targetUid + " failed: " + Libc.strerror(Libc.errno()));
            }
            Logger.debug("set uid=" + targetUid + " gid=" + targetGid);

            if (caps != null) {
                Capability.clearKeepCaps();
                Capability.applyFinalSets(caps);
            }

            // Re-set non-dumpable so /proc inspection by attached processes can't leak.
            if (Libc.prctl(Constants.PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
                Logger.debug("PR_SET_DUMPABLE,0 failed: " + Libc.strerror(Libc.errno()));
            }

            // PTY setup: if process.terminal is true and a console socket was passed,
            // open a pty, ship the master to the console socket, and wire stdio to
            // the slave. The new session leadership has to happen before wiring so the
            // slave can become the controlling terminal of this process.
            String consoleSocketPath = System.getenv("_TAKOYAKI_CONSOLE_SOCKET");
            boolean wantTerminal = spec.process != null && Boolean.TRUE.equals(spec.process.terminal);
            int ptySlave = -1;
            if (wantTerminal && consoleSocketPath != null) {
                ConsoleSocket.PtyPair pty = ConsoleSocket.openPty();
                if (pty != null) {
                    if (!ConsoleSocket.sendMasterTo(consoleSocketPath, pty.master)) {
                        Logger.warn("failed to ship pty master, falling back to no-tty");
                    } else {
                        Logger.debug("pty master sent to " + consoleSocketPath);
                        ptySlave = pty.slave;
                    }
                    PosixIO.close(pty.master);
                }
            }

            SyncChannel.writeInt32(mainSenderFd, SyncChannel.MSG_INIT_READY);
            PosixIO.close(mainSenderFd);

            if (ptySlave >= 0) {
                ConsoleSocket.wireStdio(ptySlave);
            }

            CloseRange.closeAllAbove(0);

            Logger.debug("waiting for start signal on notify fd " + notifyListenerFd);
            NotifySocket.waitForStart(notifyListenerFd);
            PosixIO.close(notifyListenerFd);

            if (spec.process == null || spec.process.args == null || spec.process.args.isEmpty()) {
                Logger.error("process.args is empty");
                PosixIO._exit(1);
                return;
            }

            Libc.clearenv();
            if (spec.process.env != null) {
                for (String entry : spec.process.env) {
                    int eq = entry.indexOf('=');
                    if (eq > 0) {
                        Libc.setenv(arena, entry.substring(0, eq), entry.substring(eq + 1), true);
                    }
                }
            }

            String[] argv = spec.process.args.toArray(new String[0]);
            Logger.info("executing: " + String.join(" ", argv));

            // Apply process.rlimits LAST — after the JVM has done all its heap
            // and address-space provisioning. If we did this earlier, a low
            // RLIMIT_AS (e.g. 1 GiB) would push the JVM's already-mapped heap
            // over the limit and the very next allocation would OOM. The
            // about-to-execve user process picks up the new limits.
            if (spec.process.rlimits != null) {
                com.ternbusty.takoyaki.syscall.Rlimit.apply(Libc.getpid(), spec.process.rlimits);
            }

            Libc.execvp(arena, argv[0], argv);
            Logger.error("execvp failed: " + Libc.strerror(Libc.errno()));
            PosixIO._exit(127);
        } catch (Exception e) {
            Logger.error("init failed: " + e.getMessage());
            PosixIO._exit(1);
        }
    }
}
