package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.apparmor.AppArmor
import com.ternbusty.takoyaki.capability.Capability
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.seccomp.Seccomp
import com.ternbusty.takoyaki.selinux.SeLinux
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Groups
import com.ternbusty.takoyaki.syscall.Libc
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

/**
 * The per-process security restriction sequence shared by the container init
 * (create/start) and `exec`. Both must end up with the same seccomp filter,
 * capability sets, LSM labels and credentials, so the sequence lives here
 * exactly once.
 *
 * The caller is expected to be the single-threaded process (or forked child)
 * that will execve into the workload next: AppArmor/SELinux labels are staged
 * on the calling thread's /proc/self/attr files and only take effect at that
 * execve.
 */
object ProcessRestrictions {

    /**
     * Apply process.oomScoreAdj via /proc/self/oom_score_adj. Inherited across
     * fork and execve, so callers run it once at a convenient (privileged)
     * point rather than inside [apply]. No-op when null.
     */
    fun applyOomScoreAdj(oomScoreAdj: Int?) {
        if (oomScoreAdj == null) return
        try {
            java.nio.file.Files.writeString(
                java.nio.file.Path.of("/proc/self/oom_score_adj"),
                oomScoreAdj.toString()
            )
            Logger.debug("oom_score_adj=$oomScoreAdj")
        } catch (e: java.io.IOException) {
            Logger.warn("write oom_score_adj failed: ${e.message}")
        }
    }

    /**
     * Apply I/O priority from the OCI process.ioPriority field. Called before
     * the restriction sequence while the process still has full privileges.
     */
    fun applyIOPriority(ioPriority: Spec.IOPriority?) {
        if (ioPriority == null) return
        // ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(class, prio))
        // IOPRIO_PRIO_VALUE(class, data) = (class << 13) | data
        val value = (ioPriority.classValue() shl 13) or ioPriority.priority
        val rc = Libc.syscall(
            Constants.NR_ioprio_set,
            Constants.IOPRIO_WHO_PROCESS.toLong(), 0L, value.toLong(), 0L, 0L
        )
        if (rc != 0L) {
            Logger.warn("ioprio_set failed: ${Libc.strerror(Libc.errno())}")
        } else {
            Logger.debug("ioprio_set class=${ioPriority.clazz} priority=${ioPriority.priority}")
        }
    }

    /**
     * Apply scheduler attributes from the OCI process.scheduler field. Called
     * before the restriction sequence while the process still has full privileges.
     *
     * Uses the raw `sched_setattr(2)` syscall with a manually-laid-out
     * `struct sched_attr` (48 bytes).
     */
    fun applyScheduler(scheduler: Spec.Scheduler?) {
        if (scheduler == null) return
        Arena.ofConfined().use { arena ->
            // struct sched_attr layout (48 bytes):
            //   u32 size           offset  0
            //   u32 sched_policy   offset  4
            //   u64 sched_flags    offset  8
            //   s32 sched_nice     offset 16
            //   u32 sched_priority offset 20
            //   u64 sched_runtime  offset 24
            //   u64 sched_deadline offset 32
            //   u64 sched_period   offset 40
            val seg = arena.allocate(48)
            seg.set(ValueLayout.JAVA_INT, 0, 48) // size
            seg.set(ValueLayout.JAVA_INT, 4, scheduler.policyValue())
            seg.set(ValueLayout.JAVA_LONG, 8, scheduler.flagBits())
            seg.set(ValueLayout.JAVA_INT, 16, scheduler.nice ?: 0)
            seg.set(ValueLayout.JAVA_INT, 20, scheduler.priority ?: 0)
            seg.set(ValueLayout.JAVA_LONG, 24, scheduler.runtime ?: 0L)
            seg.set(ValueLayout.JAVA_LONG, 32, scheduler.deadline ?: 0L)
            seg.set(ValueLayout.JAVA_LONG, 40, scheduler.period ?: 0L)
            val rc = Libc.syscall(
                Constants.NR_sched_setattr,
                0L, seg.address(), 0L, 0L, 0L
            )
            if (rc != 0L) {
                Logger.warn("sched_setattr failed: ${Libc.strerror(Libc.errno())}")
            } else {
                Logger.debug("sched_setattr policy=${scheduler.policy}")
            }
        }
    }

    /**
     * @param process        effective OCI process document; may be null
     * @param seccomp        spec.linux.seccomp; may be null
     * @param listenerState  container state serialized to a SCMP_ACT_NOTIFY
     *                       listener, if the profile has a listenerPath
     * @param seccompListenerFd pre-connected host-side listener socket, or -1
     */
    fun apply(
        process: Spec.Process?,
        seccomp: Spec.LinuxSeccomp?,
        listenerState: State,
        seccompListenerFd: Int
    ) {
        // umask: check process.user.umask first (OCI spec canonical location),
        // then fall back to process.umask for backward compatibility.
        val umaskVal: Long? = when {
            process?.user?.umask != null -> process.user.umask
            process?.umask != null -> process.umask
            else -> null
        }
        if (umaskVal != null) {
            Libc.umask(umaskVal.toInt())
        }

        // Order rationale (matches runc / youki):
        //
        //   1. AppArmor / SELinux label staging
        //   2. PR_SET_NO_NEW_PRIVS (only if spec asks)
        //   3. seccomp_load (early path) -- only when NNP is NOT requested.
        //      Rationale: seccomp(2) needs CAP_SYS_ADMIN OR a pre-set NNP
        //      (libseccomp's auto-NNP is disabled via SCMP_FLTATR_CTL_NNP=0).
        //      When NNP is off, we cannot rely on NNP so we load seccomp
        //      here while CAP_SYS_ADMIN is still in effective.
        //   4. Capability bounding set / keep_caps
        //   5. setgroups / setresgid / setresuid
        //   6. capset (final effective/permitted/inheritable/ambient)
        //   7. PR_SET_DUMPABLE=0
        //   8. seccomp_load (late path) -- only when NNP IS requested.
        //      NNP satisfies seccomp's permission check without CAP_SYS_ADMIN,
        //      so we defer the load past the cap drop. This keeps our own
        //      post-drop syscalls (capset, etc.) out from under the filter
        //      and lets the profile focus on the workload only.
        //   9. caller execve's into the user process

        val nnpRequested = process != null && process.noNewPrivileges == true

        if (process?.apparmorProfile != null) {
            AppArmor.apply(process.apparmorProfile)
        }
        if (process?.selinuxLabel != null) {
            SeLinux.apply(process.selinuxLabel)
        }

        if (nnpRequested) {
            if (Libc.prctl(Constants.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                Logger.warn("PR_SET_NO_NEW_PRIVS failed")
            } else {
                Logger.debug("no_new_privileges set")
            }
        }

        // Early seccomp: NNP not set, so we need CAP_SYS_ADMIN which is still
        // in effective at this point.
        if (seccomp != null && !nnpRequested) {
            Seccomp.apply(seccomp, listenerState, seccompListenerFd)
        }

        val caps: Spec.LinuxCapabilities? = process?.capabilities
        if (caps != null) {
            Capability.applyBoundingSet(caps)
            Capability.setKeepCaps()
        }

        if (process?.user?.additionalGids != null) {
            Groups.setAdditional(process.user.additionalGids)
        }

        val targetGid = process?.user?.gid ?: 0
        val targetUid = process?.user?.uid ?: 0
        // setresgid/setresuid drops real/effective/saved IDs all at once so the
        // process can't restore privileges via saved UID.
        if (Libc.setresgid(targetGid, targetGid, targetGid) != 0) {
            Logger.warn("setresgid $targetGid failed: ${Libc.strerror(Libc.errno())}")
        }
        if (Libc.setresuid(targetUid, targetUid, targetUid) != 0) {
            Logger.warn("setresuid $targetUid failed: ${Libc.strerror(Libc.errno())}")
        }
        Logger.debug("set uid=$targetUid gid=$targetGid")

        if (caps != null) {
            Capability.clearKeepCaps()
            Capability.applyFinalSets(caps)
        }

        // Re-set non-dumpable so /proc inspection by attached processes can't leak.
        if (Libc.prctl(Constants.PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
            Logger.debug("PR_SET_DUMPABLE,0 failed: ${Libc.strerror(Libc.errno())}")
        }

        // Late seccomp: NNP is set, so we can install seccomp without
        // CAP_SYS_ADMIN. Deferring past cap drop keeps the filter focused on
        // the workload and off our own setup syscalls.
        if (seccomp != null && nnpRequested) {
            Seccomp.apply(seccomp, listenerState, seccompListenerFd)
        }
    }
}
