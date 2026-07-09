package com.ternbusty.takoyaki.process;

import com.ternbusty.takoyaki.cgroup.Cgroup;
import com.ternbusty.takoyaki.config.KontainerConfig;
import com.ternbusty.takoyaki.hooks.Hooks;
import com.ternbusty.takoyaki.ipc.SyncChannel;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.rootless.Rootless;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class MainProcess {
    private MainProcess() {}

    public static void run(int stage1Pid, int syncFd, Spec spec, String containerId,
                           String bundlePath, String rootPath, String pidFile,
                           int notifyListenerFd, int mainSenderFd) {
        Logger.setContext("main");
        Logger.debug("main proc started; stage1=" + stage1Pid);
        if (Logger.isDebugEnabled()) {
            try {
                String mntNs = java.nio.file.Files.readSymbolicLink(java.nio.file.Path.of("/proc/self/ns/mnt")).toString();
                Logger.debug("main mnt_ns=" + mntNs);
            } catch (Exception e) {}
        }

        try {
            if (spec.linux != null && spec.linux.cgroupsPath != null) {
                Cgroup.setup(stage1Pid, spec.linux.cgroupsPath, spec.linux);
            }
            // rlimits are NOT applied to the bootstrap pid from here — doing so
            // forces them on the freshly-spawned Java init, and a low RLIMIT_AS
            // (e.g. the OCI runtime-tools process_rlimits test sets 1 GiB soft)
            // makes GraalVM's main isolate fail to create. They're applied
            // inside InitProcess, AFTER the JVM has come up, so only the user
            // process inherits the spec's resource caps.

            boolean hasUserNs = spec.hasNamespace("user");
            if (hasUserNs) {
                int req = SyncChannel.readInt32(syncFd);
                if (req != SyncChannel.MSG_USERMAP_PLS) {
                    throw new RuntimeException("expected USERMAP_PLS, got 0x" + Integer.toHexString(req));
                }
                int bootstrapPid = SyncChannel.readInt32(syncFd);
                Logger.debug("writing uid/gid map for pid " + bootstrapPid);

                long euid = Libc.geteuid();
                String uidMap = buildIdMapping(spec.linux != null ? spec.linux.uidMappings : null, euid);
                String gidMap = buildIdMapping(spec.linux != null ? spec.linux.gidMappings : null, euid);

                boolean privileged = !Rootless.isRootless();

                // Rootless path: writing maps with multiple ranges requires the
                // newuidmap/newgidmap setuid helpers from shadow-utils.
                boolean wroteViaHelper = false;
                if (!privileged && spec.linux != null
                        && (multiRange(spec.linux.uidMappings) || multiRange(spec.linux.gidMappings))) {
                    Logger.debug("rootless detected, attempting newuidmap/newgidmap");
                    wroteViaHelper =
                            Rootless.writeUidMap(bootstrapPid, spec.linux.uidMappings)
                            && Rootless.writeGidMap(bootstrapPid, spec.linux.gidMappings);
                }
                if (!wroteViaHelper) {
                    // Direct write path. An unprivileged caller cannot write
                    // gid_map without first disabling setgroups(2) in the new
                    // userns — that's the kernel's substitute for CAP_SETGID.
                    // Writing "deny" is irreversible and disables setgroups(2)
                    // for the container's entire lifetime, so we only do it
                    // when we actually need to (i.e. the helper wasn't used).
                    if (!privileged) {
                        try {
                            Files.writeString(Path.of("/proc/" + bootstrapPid + "/setgroups"), "deny\n");
                        } catch (IOException e) {
                            Logger.warn("setgroups write failed: " + e.getMessage());
                        }
                    }
                    Files.writeString(Path.of("/proc/" + bootstrapPid + "/uid_map"), uidMap);
                    Files.writeString(Path.of("/proc/" + bootstrapPid + "/gid_map"), gidMap);
                }

                SyncChannel.writeInt32(syncFd, SyncChannel.MSG_USERMAP_ACK);
                Logger.debug("user map written");
            }

            int stage2Pid = SyncChannel.readInt32(syncFd);
            Logger.debug("received stage-2 pid=" + stage2Pid);
            PosixIO.close(syncFd);
            PosixIO.close(notifyListenerFd);

            if (spec.linux != null && spec.linux.cgroupsPath != null) {
                // The first Cgroup.setup (for stage1Pid) already created the
                // directory, enabled controllers, applied limits, and attached
                // the device BPF program for this same cgroupPath. Re-running
                // setup would stack a second identical device filter, so only
                // move the final init pid into the cgroup here.
                Cgroup.addPid(spec.linux.cgroupsPath, stage2Pid);
            }

            int initReady = SyncChannel.readInt32(mainSenderFd);
            if (initReady != SyncChannel.MSG_INIT_READY) {
                throw new RuntimeException("expected INIT_READY, got 0x" + Integer.toHexString(initReady));
            }
            PosixIO.close(mainSenderFd);
            Logger.debug("init ready");

            State state = State.create(spec.ociVersion, containerId,
                    ContainerStatus.CREATED, stage2Pid, bundlePath, spec.annotations);
            state.save(rootPath);

            new KontainerConfig(spec.linux != null ? spec.linux.cgroupsPath : null)
                    .save(rootPath, containerId);

            // prestart (deprecated, but still emitted by some tools) and createRuntime hooks
            // both fire in the runtime namespace after the container is configured but
            // before the user process is started.
            if (spec.hooks != null) {
                // prestart (deprecated) and createRuntime are FAILABLE per OCI
                // spec — a non-zero exit MUST abort create. The exception
                // propagates up to the surrounding catch which _exit(1)s.
                Hooks.runFailFast(spec.hooks.prestart, state, "prestart");
                Hooks.runFailFast(spec.hooks.createRuntime, state, "createRuntime");
            }

            if (pidFile != null) {
                Files.writeString(Path.of(pidFile), Integer.toString(stage2Pid));
            }

            Logger.info("container " + containerId + " created with init pid " + stage2Pid);
            // Historically this called System.exit(0). That broke RunCommand,
            // which needs to keep the JVM alive after create to call start +
            // waitpid + delete in the same process. Returning normally lets the
            // caller decide whether to exit (CreateCommand top-level) or
            // continue (RunCommand foreground path).
        } catch (Exception e) {
            Logger.error("main proc failed: " + e.getMessage());
            e.printStackTrace(System.err);
            PosixIO.close(syncFd);
            PosixIO.close(notifyListenerFd);
            PosixIO._exit(1);
        }
    }

    /**
     * Render a uid_map / gid_map file body from OCI id-mapping entries.
     *
     * Package-visible so unit tests can pin the wire format: each line is
     * "{@code containerID hostID size\n}" with no header, no trailing blank.
     * When {@code mappings} is null/empty we fall back to identity-mapping
     * {@code fallbackEuid}, the caller's effective uid (handy for rootless
     * quick boot).
     */
    static String buildIdMapping(List<Spec.IdMapping> mappings, long fallbackEuid) {
        if (mappings == null || mappings.isEmpty()) {
            return "0 " + fallbackEuid + " 1\n";
        }
        StringBuilder sb = new StringBuilder();
        for (Spec.IdMapping m : mappings) {
            sb.append(m.containerID).append(' ')
              .append(m.hostID).append(' ')
              .append(m.size).append('\n');
        }
        return sb.toString();
    }

    /**
     * True if the mapping list has more than one entry OR a single entry with
     * size > 1. That's the trigger for routing through newuidmap/newgidmap
     * (the kernel only allows a single 1-row identity map via direct write
     * unless we have CAP_SETUID/CAP_SETGID on the host).
     *
     * Package-visible for tests.
     */
    static boolean multiRange(List<Spec.IdMapping> m) {
        return m != null && m.size() > 0 && (m.size() > 1 || m.get(0).size > 1);
    }
}
