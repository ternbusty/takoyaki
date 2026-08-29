package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.hooks.Hooks
import com.ternbusty.takoyaki.ipc.SyncChannel
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.rootless.Rootless
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.nio.file.Files
import java.nio.file.Path

object MainProcess {

    fun run(
        stage1Pid: Int,
        syncFd: Int,
        spec: Spec,
        containerId: String,
        bundlePath: String,
        rootPath: String,
        pidFile: String?,
        notifyListenerFd: Int,
        mainSenderFd: Int,
        pidfdSocket: String?
    ) {
        Logger.context = "main"
        Logger.debug("main proc started; stage1=$stage1Pid")
        if (Logger.isDebugEnabled) {
            try {
                val mntNs = Files.readSymbolicLink(Path.of("/proc/self/ns/mnt")).toString()
                Logger.debug("main mnt_ns=$mntNs")
            } catch (_: Exception) {
            }
        }

        // runc compat: assign a default cgroup path when none is specified.
        // Many bats tests (pause, events, update, cpu_affinity) rely on the
        // container having a cgroup without explicitly setting cgroupsPath.
        var effectiveCgroupsPath = spec.linux?.cgroupsPath
        if (effectiveCgroupsPath == null) {
            effectiveCgroupsPath = "takoyaki/$containerId"
            Logger.debug("no cgroupsPath in spec, defaulting to $effectiveCgroupsPath")
        }

        var stage2Pid = -1
        // Track whether the cgroup existed before we tried to create it.
        // On failure we must NOT clean up a pre-existing cgroup: doing so
        // would kill another container's processes (e.g. ct1 in the runc
        // "non-empty cgroup" test) and remove a frozen cgroup the test set up.
        val cgroupPreExisted = Files.exists(
            Cgroup.dir(effectiveCgroupsPath).resolve("cgroup.procs")
        )
        try {
            Cgroup.setup(stage1Pid, effectiveCgroupsPath, spec.linux)
            // rlimits are NOT applied to the bootstrap pid from here -- doing so
            // forces them on the freshly-spawned Java init, and a low RLIMIT_AS
            // (e.g. the OCI runtime-tools process_rlimits test sets 1 GiB soft)
            // makes GraalVM's main isolate fail to create. They're applied
            // inside InitProcess, AFTER the JVM has come up, so only the user
            // process inherits the spec's resource caps.

            // The uid/gid map handshake only happens when the user namespace
            // is being *created* (no .path on the namespace entry). When the
            // config specifies a .path the bootstrap joins that existing userns
            // via setns(2) and never sends SYNC_USERMAP_PLS.
            val creatingUserNs = spec.isCreatingNamespace("user")
            if (creatingUserNs) {
                val req = SyncChannel.readInt32(syncFd)
                if (req != SyncChannel.MSG_USERMAP_PLS) {
                    throw RuntimeException("expected USERMAP_PLS, got 0x${Integer.toHexString(req)}")
                }
                val bootstrapPid = SyncChannel.readInt32(syncFd)
                Logger.debug("writing uid/gid map for pid $bootstrapPid")

                val euid = Libc.geteuid().toLong()
                val uidMap = buildIdMapping(spec.linux?.uidMappings, euid)
                val gidMap = buildIdMapping(spec.linux?.gidMappings, euid)

                val privileged = !Rootless.isRootless()

                // Rootless path: writing maps with multiple ranges requires the
                // newuidmap/newgidmap setuid helpers from shadow-utils.
                var wroteViaHelper = false
                val specLinux = spec.linux
                if (!privileged && specLinux != null
                    && (multiRange(specLinux.uidMappings) || multiRange(specLinux.gidMappings))
                ) {
                    Logger.debug("rootless detected, attempting newuidmap/newgidmap")
                    wroteViaHelper =
                        Rootless.writeUidMap(bootstrapPid, specLinux.uidMappings)
                                && Rootless.writeGidMap(bootstrapPid, specLinux.gidMappings)
                }
                if (!wroteViaHelper) {
                    // Direct write path. An unprivileged caller cannot write
                    // gid_map without first disabling setgroups(2) in the new
                    // userns -- that's the kernel's substitute for CAP_SETGID.
                    // Writing "deny" is irreversible and disables setgroups(2)
                    // for the container's entire lifetime, so we only do it
                    // when we actually need to (i.e. the helper wasn't used).
                    if (!privileged) {
                        try {
                            Files.writeString(Path.of("/proc/$bootstrapPid/setgroups"), "deny\n")
                        } catch (e: IOException) {
                            Logger.warn("setgroups write failed: ${e.message}")
                        }
                    }
                    Files.writeString(Path.of("/proc/$bootstrapPid/uid_map"), uidMap)
                    Files.writeString(Path.of("/proc/$bootstrapPid/gid_map"), gidMap)
                }

                SyncChannel.writeInt32(syncFd, SyncChannel.MSG_USERMAP_ACK)
                Logger.debug("user map written")
            }

            stage2Pid = SyncChannel.readInt32(syncFd)
            Logger.debug("received stage-2 pid=$stage2Pid")
            PosixIO.close(notifyListenerFd)

            // Move network devices into the container's network namespace.
            // Must happen after the init has created its namespaces (we have its
            // pid) and before the init configures networking inside them.
            if (!spec.linux?.netDevices.isNullOrEmpty()) {
                com.ternbusty.takoyaki.network.NetDevice.moveDevices(
                    spec.linux!!.netDevices, stage2Pid
                )
            }

            // The first Cgroup.setup (for stage1Pid) already created the
            // directory, enabled controllers, applied limits, and attached
            // the device BPF program for this same cgroupPath. Re-running
            // setup would stack a second identical device filter, so only
            // move the final init pid into the cgroup here.
            Cgroup.addPid(effectiveCgroupsPath, stage2Pid.toLong())
            // runc compat: reset CPU affinity to all CPUs after cgroup
            // assignment, so the container inherits the cpuset mask rather
            // than the parent's (potentially restricted) affinity.
            resetCpuAffinity(stage2Pid)

            // Notify stage-1 that the init process has been moved to the
            // container's cgroup. Stage-1 forwards this to stage-2, which
            // then calls unshare(CLONE_NEWCGROUP) so the cgroupns root is
            // the container's cgroup (not the parent's).
            // Only send CGROUP_ACK when the spec creates a new cgroup
            // namespace. bootstrap.c's stage-1 reads CGROUP_ACK only when
            // CLONE_NEWCGROUP is in the clone flags. Writing it
            // unconditionally causes EPIPE when stage-1 has already exited
            // (it doesn't wait for CGROUP_ACK when there's no cgroup ns).
            val creatingCgroupNs = spec.isCreatingNamespace("cgroup")
            if (creatingCgroupNs) {
                SyncChannel.writeInt32(syncFd, SyncChannel.MSG_CGROUP_ACK)
            }
            PosixIO.close(syncFd)

            val initReady = SyncChannel.readInt32(mainSenderFd)
            if (initReady != SyncChannel.MSG_INIT_READY) {
                throw RuntimeException("expected INIT_READY, got 0x${Integer.toHexString(initReady)}")
            }
            PosixIO.close(mainSenderFd)
            Logger.debug("init ready")

            // Apply pids.max now that the init process has fully initialized.
            // This is deferred from Cgroup.setup because the Java init
            // process needs multiple threads (for GraalVM internals) during
            // startup. A low pids.max (e.g. 1 from pids.limit=0) would
            // prevent the init from starting if applied before INIT_READY.
            Cgroup.applyDeferredPids(effectiveCgroupsPath, spec.linux?.resources)
            // Attach the eBPF device cgroup program now that the init has
            // finished creating device nodes (mknod) during rootfs setup.
            // Attaching earlier would block mknod for spec.linux.devices
            // entries that are not in the allow list.
            Cgroup.applyDeferredDevices(effectiveCgroupsPath, spec.linux?.resources)

            val state = State.create(
                spec.ociVersion, containerId,
                ContainerStatus.CREATED, stage2Pid, bundlePath, spec.annotations
            )
            state.save(rootPath)

            val noNewKeyring = "1" == System.getenv("_TAKOYAKI_NO_NEW_KEYRING")
            KontainerConfig(effectiveCgroupsPath, noNewKeyring)
                .save(rootPath, containerId)

            // prestart (deprecated, but still emitted by some tools) and createRuntime hooks
            // both fire in the runtime namespace after the container is configured but
            // before the user process is started.
            val specHooks = spec.hooks
            if (specHooks != null) {
                // prestart (deprecated) and createRuntime are FAILABLE per OCI
                // spec -- a non-zero exit MUST abort create. The exception
                // propagates up to the surrounding catch which _exit(1)s.
                Hooks.runFailFast(specHooks.prestart, state, "prestart")
                Hooks.runFailFast(specHooks.createRuntime, state, "createRuntime")
            }

            if (pidFile != null) {
                try {
                    Files.writeString(Path.of(pidFile), stage2Pid.toString())
                } catch (_: java.nio.file.NoSuchFileException) {
                    throw RuntimeException("open $pidFile: no such file or directory")
                }
            }

            if (pidfdSocket != null) {
                com.ternbusty.takoyaki.console.PidfdSocket.sendPidfd(pidfdSocket, stage2Pid)
            }

            Logger.info("container $containerId created with init pid $stage2Pid")
            // Historically this called System.exit(0). That broke RunCommand,
            // which needs to keep the JVM alive after create to call start +
            // waitpid + delete in the same process. Returning normally lets the
            // caller decide whether to exit (CreateCommand top-level) or
            // continue (RunCommand foreground path).
        } catch (e: Exception) {
            // Print runc-compatible error message to stderr. Java stack traces
            // confuse bats tests that assert on specific error patterns.
            val msg = e.message
            if (msg != null) {
                System.err.println(msg)
            }
            Logger.error("main proc failed: $msg")
            // Clean up container state on failure so the container name is
            // not left in a zombie "exists" state. runc does the same when
            // hooks fail or any create-time error occurs.
            try {
                val stateDir = State.containerDir(rootPath, containerId)
                if (Files.exists(stateDir)) {
                    Files.walk(stateDir).use { walk ->
                        walk.sorted(Comparator.reverseOrder()).forEach { p ->
                            try {
                                Files.deleteIfExists(p)
                            } catch (_: IOException) {
                            }
                        }
                    }
                }
            } catch (_: Exception) {
            }
            // Kill the init process so it doesn't linger.
            if (stage2Pid > 0) {
                try {
                    Libc.kill(stage2Pid, 9)
                } catch (_: Exception) {
                }
            }
            // Clean up the cgroup directory only if it did not pre-exist.
            // A pre-existing cgroup belongs to another container; cleaning it
            // would kill that container's processes and break tests like
            // "should error for a non-empty cgroup" and "refuse frozen cgroup".
            if (!cgroupPreExisted) {
                try {
                    Cgroup.cleanup(effectiveCgroupsPath)
                } catch (_: Exception) {
                }
            }
            PosixIO.close(syncFd)
            PosixIO.close(notifyListenerFd)
            PosixIO._exit(1)
        }
    }

    /**
     * Reset the CPU affinity of pid to include all possible CPUs. The kernel
     * clamps the mask to the cpuset of the target's cgroup, so the effective
     * affinity becomes the cgroup cpuset. This matches runc's
     * tryResetCPUAffinity. Errors are non-fatal (logged at debug).
     */
    private fun resetCpuAffinity(pid: Int) {
        Arena.ofConfined().use { arena ->
            // cpu_set_t on Linux is 1024 bits = 128 bytes. Fill it with all-ones.
            val size = 128
            val mask: MemorySegment = arena.allocate(size.toLong())
            mask.fill(0xFF.toByte())
            val rc = Libc.syscall(
                com.ternbusty.takoyaki.syscall.Constants.NR_sched_setaffinity,
                pid.toLong(), size.toLong(), mask.address(), 0L, 0L
            )
            if (rc != 0L) {
                Logger.debug("sched_setaffinity($pid) failed: ${Libc.strerror(Libc.errno())}")
            } else {
                Logger.debug("reset CPU affinity for pid $pid")
            }
        }
    }

    /**
     * Render a uid_map / gid_map file body from OCI id-mapping entries.
     *
     * Package-visible so unit tests can pin the wire format: each line is
     * "`containerID hostID size\n`" with no header, no trailing blank.
     * When [mappings] is null/empty we fall back to identity-mapping
     * [fallbackEuid], the caller's effective uid (handy for rootless
     * quick boot).
     */
    internal fun buildIdMapping(mappings: List<Spec.IdMapping>?, fallbackEuid: Long): String {
        if (mappings.isNullOrEmpty()) {
            return "0 $fallbackEuid 1\n"
        }
        val sb = StringBuilder()
        for (m in mappings) {
            sb.append(m.containerID).append(' ')
                .append(m.hostID).append(' ')
                .append(m.size).append('\n')
        }
        return sb.toString()
    }

    /**
     * True if the mapping list has more than one entry OR a single entry with
     * size > 1. That's the trigger for routing through newuidmap/newgidmap
     * (the kernel only allows a single 1-row identity map via direct write
     * unless we have CAP_SETUID/CAP_SETGID on the host).
     *
     * Package-visible for tests.
     */
    internal fun multiRange(m: List<Spec.IdMapping>?): Boolean =
        m != null && m.isNotEmpty() && (m.size > 1 || m[0].size > 1)
}
