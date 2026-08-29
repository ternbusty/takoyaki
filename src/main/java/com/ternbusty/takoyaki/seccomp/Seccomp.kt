package com.ternbusty.takoyaki.seccomp

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.gen.NativeH
import com.ternbusty.takoyaki.syscall.gen.scmp_arg_cmp

import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * libseccomp facade over the jextract-generated [NativeH] bindings. The
 * plumbing moved from hand-written FFM downcalls to generated ones; the filter
 * semantics are unchanged.
 */
class Seccomp private constructor() {

    companion object {

        /** libseccomp action code for SCMP_ACT_NOTIFY, from seccomp.h. */
        private val ACT_NOTIFY = NativeH.SCMP_ACT_NOTIFY()

        /**
         * Force libseccomp to be dlopen'd now. Must run before pivot_root cuts the
         * process off from the host filesystem: the container rootfs does not ship
         * libseccomp and the C bootstrap only preloads libc/libm/libdl/libpthread/
         * librt. Touching any NativeH entry point triggers its class initializer,
         * whose `libraryLookup("libseccomp.so.2")` loads the library.
         */
        fun preload(): Boolean = ensureLoaded()

        @Synchronized
        private fun ensureLoaded(): Boolean =
            try {
                Arena.ofConfined().use { arena ->
                    // Harmless call — resolves a syscall name — that forces NativeH's
                    // <clinit> (the library load) to run and surfaces a load failure.
                    NativeH.seccomp_syscall_resolve_name(arena.allocateFrom("read"))
                }
                true
            } catch (t: Throwable) {
                Logger.warn("libseccomp not loadable: ${t.message}")
                false
            }

        /**
         * @param state          used only when SCMP_ACT_NOTIFY rules are present and
         *                       `sec.listenerPath` is set; serialized as the state
         *                       JSON sent to the listener.
         * @param preConnectedFd host-side pre-connected listener socket fd, or -1 when
         *                       absent (the listener path must then be reachable from
         *                       here, which it usually isn't post-pivot).
         */
        fun apply(sec: LinuxSeccomp?, state: State, preConnectedFd: Int) {
            if (sec == null) return
            if (!ensureLoaded()) {
                Logger.error("libseccomp.so.2 not found, cannot apply seccomp")
                return
            }
            try {
                Arena.ofConfined().use { arena ->
                    val defaultAction = actionToken(sec.defaultAction, sec.defaultErrnoRet)
                    val ctx = NativeH.seccomp_init(defaultAction)
                    if (ctx == null || ctx.address() == 0L) {
                        Logger.error("seccomp_init returned NULL")
                        return
                    }
                    try {
                        // libseccomp defaults SCMP_FLTATR_CTL_NNP to 1, which makes
                        // seccomp_load() unconditionally call prctl(PR_SET_NO_NEW_PRIVS, 1).
                        // That breaks specs that set noNewPrivileges=false and would also
                        // mask cases where the runtime is supposed to be in charge of NNP.
                        // Disable libseccomp's auto-NNP — the runtime sets NNP earlier
                        // based on spec.process.noNewPrivileges.
                        NativeH.seccomp_attr_set(ctx, NativeH.SCMP_FLTATR_CTL_NNP(), 0)

                        // Translate the OCI spec's filter flags into the libseccomp
                        // attributes that back them. When no flags field is present in
                        // the spec, default to SPEC_ALLOW (matches runc behaviour).
                        // Unknown flags are warned about rather than ignored so the
                        // caller sees the mismatch.
                        //
                        // filterFlagsValue tracks the numeric seccomp(2) flags that
                        // libseccomp will pass to the kernel. TSYNC contributes 0
                        // because libseccomp handles it internally through its own
                        // attribute, not through the kernel flags argument.
                        var filterFlagsValue = 0
                        val flags = sec.flags
                        if (flags != null) {
                            for (flag in flags) {
                                when (flag) {
                                    "SECCOMP_FILTER_FLAG_TSYNC" -> {
                                        NativeH.seccomp_attr_set(ctx, NativeH.SCMP_FLTATR_CTL_TSYNC(), 1)
                                        // TSYNC contributes 0 to the kernel flags
                                    }
                                    "SECCOMP_FILTER_FLAG_LOG" -> {
                                        NativeH.seccomp_attr_set(ctx, NativeH.SCMP_FLTATR_CTL_LOG(), 1)
                                        filterFlagsValue = filterFlagsValue or 2
                                    }
                                    "SECCOMP_FILTER_FLAG_SPEC_ALLOW" -> {
                                        NativeH.seccomp_attr_set(ctx, NativeH.SCMP_FLTATR_CTL_SSB(), 1)
                                        filterFlagsValue = filterFlagsValue or 4
                                    }
                                    "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV" -> {
                                        // SCMP_FLTATR_CTL_WAITKILL = 10 (libseccomp 2.5.4+)
                                        val rc = NativeH.seccomp_attr_set(ctx, 10, 1)
                                        if (rc != 0) {
                                            throw RuntimeException(
                                                "error adding WaitKill flag to seccomp filter: " +
                                                "SetWaitKill requires libseccomp >= 2.5.4 and kernel >= 5.19"
                                            )
                                        }
                                        filterFlagsValue = filterFlagsValue or 0x20
                                    }
                                    else -> Logger.warn("unknown seccomp filter flag: $flag")
                                }
                            }
                        } else {
                            // No flags field in the spec: default to SPEC_ALLOW.
                            NativeH.seccomp_attr_set(ctx, NativeH.SCMP_FLTATR_CTL_SSB(), 1)
                            filterFlagsValue = 4
                        }
                        // Ask libseccomp to compile the rule set into a binary tree
                        // once it gets large enough for the linear match to hurt.
                        // Docker's default profile has hundreds of syscalls; without
                        // this every allowed syscall pays for walking the whole list.
                        // runc uses the same 32-rule threshold.
                        val syscalls = sec.syscalls
                        if (syscalls != null && countSyscalls(syscalls) > 32) {
                            NativeH.seccomp_attr_set(ctx, NativeH.SCMP_FLTATR_CTL_OPTIMIZE(), 2)
                        }

                        // architectures - libseccomp wants lowercase, no SCMP_ARCH_ prefix
                        val architectures = sec.architectures
                        if (architectures != null) {
                            for (archName in architectures) {
                                val n = archName.removePrefix("SCMP_ARCH_").lowercase()
                                val nameSeg = arena.allocateFrom(n)
                                val token = NativeH.seccomp_arch_resolve_name(nameSeg)
                                if (token == 0) {
                                    Logger.warn("unknown seccomp arch: $archName")
                                    continue
                                }
                                NativeH.seccomp_arch_add(ctx, token)
                            }
                        }

                        var hasNotify = false
                        if (syscalls != null) {
                            for (sc in syscalls) {
                                val action = actionToken(sc.action, sc.errnoRet)
                                if (action == ACT_NOTIFY) hasNotify = true
                                if (sc.names == null) continue
                                // SCMP_ACT_NOTIFY on write(2) is a deadlock trap: the
                                // supervisor process reads the notify fd, and its
                                // response typically involves writing back through the
                                // same syscall the container just called. runc and
                                // youki both refuse this combination up front.
                                if (sc.action == "SCMP_ACT_NOTIFY" && sc.names?.contains("write") == true) {
                                    throw RuntimeException(
                                        "SCMP_ACT_NOTIFY cannot be used for the write syscall"
                                    )
                                }
                                for (name in sc.names) {
                                    val nameSeg = arena.allocateFrom(name)
                                    val nr = NativeH.seccomp_syscall_resolve_name(nameSeg)
                                    if (nr == NativeH.__NR_SCMP_ERROR()) {
                                        Logger.debug("syscall $name unknown to libseccomp, skipping")
                                        continue
                                    }
                                    // libseccomp returns negative "pseudo-syscall" numbers
                                    // for syscalls that exist on at least one architecture
                                    // but not on the native one (e.g. mknod on aarch64,
                                    // resolved as a non-native pseudo). Pass them through
                                    // anyway — libseccomp records them in the multi-arch
                                    // rule set, and importantly still sets col->notify_used
                                    // when action == SCMP_ACT_NOTIFY. Skipping would silently
                                    // drop the notify state and seccomp_notify_fd would then
                                    // return -EFAULT.
                                    val args = sc.args
                                    if (args == null || args.isEmpty()) {
                                        // Use seccomp_rule_add_array even with zero args. The
                                        // variadic seccomp_rule_add silently mis-loads the
                                        // notify state under Panama FFM (seccomp_notify_fd
                                        // returns -EFAULT afterwards), while the non-variadic
                                        // array variant works.
                                        val rc = NativeH.seccomp_rule_add_array(
                                            ctx, action, nr, 0, MemorySegment.NULL
                                        )
                                        if (rc != 0) {
                                            Logger.debug("rule_add $name failed: $rc")
                                        }
                                    } else {
                                        addRulesWithOrSplit(arena, ctx, action, nr, args)
                                    }
                                }
                            }
                        }

                        // Log the effective filter flags. When SCMP_ACT_NOTIFY rules
                        // are present, libseccomp internally adds NEW_LISTENER (0x08)
                        // to the kernel flags passed to seccomp(2). Include it in the
                        // reported value so the debug output matches runc.
                        var reportedFlags = filterFlagsValue
                        if (hasNotify) {
                            reportedFlags = reportedFlags or 0x08 // SECCOMP_FILTER_FLAG_NEW_LISTENER
                        }
                        Logger.debug("seccomp filter flags: $reportedFlags")

                        val loadRc = NativeH.seccomp_load(ctx)
                        if (loadRc != 0) {
                            // Silently returning here would let the container come up
                            // with no filter at all, which is worse than failing to
                            // start — the user requested a seccomp policy and the
                            // runtime is now serving one that does not exist. Bail so
                            // the surrounding init aborts.
                            throw RuntimeException("seccomp_load failed: $loadRc")
                        }
                        Logger.info("seccomp filter loaded")

                        // runc compat (patchbpf): install a second BPF filter that
                        // returns ENOSYS for syscall numbers beyond the native arch's
                        // known range. Without this stub, unknown/future syscalls hit
                        // the libseccomp default action (typically ERRNO+EPERM) instead
                        // of the expected ENOSYS.
                        // The BPF stub is a plain ALLOW/ENOSYS filter (no NOTIFY
                        // actions), so strip NEW_LISTENER and WAIT_KILLABLE_RECV
                        // which are only valid when paired with a notify fd.
                        val stubFlags = filterFlagsValue and (0x08 or 0x20).inv()
                        installEnosysStub(arena, syscalls, stubFlags)

                        // If the spec declared any SCMP_ACT_NOTIFY rules, pull the notify fd
                        // out of the loaded context. We don't manage a listener — that's the
                        // caller's responsibility — but make the fd reachable via env var.
                        if (hasNotify) {
                            Logger.debug(
                                "seccomp ctx address=0x${java.lang.Long.toHexString(ctx.address())}" +
                                " (about to call seccomp_notify_fd)"
                            )
                            val notifyFd = NativeH.seccomp_notify_fd(ctx)
                            if (notifyFd < 0) {
                                Logger.warn("seccomp_notify_fd returned $notifyFd")
                            } else if (sec.listenerPath.isNullOrEmpty()) {
                                Logger.warn(
                                    "SCMP_ACT_NOTIFY rules present but no listenerPath; " +
                                    "leaving notify fd=$notifyFd" +
                                    " unforwarded — matching syscalls will block forever"
                                )
                            } else {
                                SeccompListener.forward(
                                    sec.listenerPath ?: "", state,
                                    sec.listenerMetadata, notifyFd, preConnectedFd
                                )
                                // Close our copy; the listener has its own dup via SCM_RIGHTS.
                                com.ternbusty.takoyaki.syscall.PosixIO.close(notifyFd)
                            }
                        }
                    } finally {
                        NativeH.seccomp_release(ctx)
                    }
                }
            } catch (e: RuntimeException) {
                // Rethrow runtime errors (validation failures like write+NOTIFY,
                // seccomp_load failures) so the caller can abort.
                Logger.error("seccomp apply error: ${e.message}")
                throw e
            } catch (t: Throwable) {
                Logger.error("seccomp apply error: ${t.message}")
                throw RuntimeException(t)
            }
        }

        /**
         * Split args that reference the same index into separate rule_add calls
         * (OR semantics). Args with distinct indices within each group are passed
         * as a single rule_add call (AND semantics within the group).
         *
         * Example: args [{index=0, op=EQ, val=100}, {index=0, op=EQ, val=9001}]
         * produces two rule_add calls, one for each arg0 value. This matches
         * runc's matchCall() splitting logic.
         */
        private fun addRulesWithOrSplit(
            arena: Arena, ctx: MemorySegment, action: Int, nr: Int,
            args: List<SeccompArg>
        ) {
            // Group args by index. If all indices are unique, we can use a single rule.
            val byIndex = LinkedHashMap<Int, MutableList<SeccompArg>>()
            for (a in args) {
                byIndex.getOrPut(a.index) { mutableListOf() }.add(a)
            }
            val hasDuplicateIndex = byIndex.values.any { it.size > 1 }
            if (!hasDuplicateIndex) {
                // Simple case: all unique indices, single AND rule.
                val rc = addRuleWithArgs(arena, ctx, action, nr, args)
                if (rc != 0) Logger.debug("rule_add failed: $rc")
                return
            }
            // Generate the Cartesian product of per-index arg groups.
            // Each combination becomes one rule_add call.
            val groups = ArrayList(byIndex.values)
            var combos: MutableList<MutableList<SeccompArg>> = mutableListOf(mutableListOf())
            for (group in groups) {
                val next = mutableListOf<MutableList<SeccompArg>>()
                for (prefix in combos) {
                    for (a in group) {
                        val combo = ArrayList(prefix)
                        combo.add(a)
                        next.add(combo)
                    }
                }
                combos = next
            }
            for (combo in combos) {
                val rc = addRuleWithArgs(arena, ctx, action, nr, combo)
                if (rc != 0) Logger.debug("rule_add (OR split) failed: $rc")
            }
        }

        /**
         * Encode SeccompArg entries into struct scmp_arg_cmp[] and call seccomp_rule_add_array.
         * struct scmp_arg_cmp layout: unsigned int arg; enum scmp_compare op; uint64_t datum_a; uint64_t datum_b.
         * Offsets come from the jextract-generated [scmp_arg_cmp] (header-derived), not a
         * hand-computed stride.
         */
        private fun addRuleWithArgs(
            arena: Arena, ctx: MemorySegment, action: Int, nr: Int,
            args: List<SeccompArg>
        ): Int {
            val n = args.size
            val arr = scmp_arg_cmp.allocateArray(n.toLong(), arena)
            for (i in 0 until n) {
                val a = args[i]
                val e = scmp_arg_cmp.asSlice(arr, i.toLong())
                scmp_arg_cmp.arg(e, a.index)
                scmp_arg_cmp.op(e, mapCompare(a.op))
                scmp_arg_cmp.datum_a(e, a.value)
                scmp_arg_cmp.datum_b(e, a.valueTwo ?: 0)
            }
            return NativeH.seccomp_rule_add_array(ctx, action, nr, n, arr)
        }

        private fun mapCompare(op: String?): Int {
            if (op == null) return 0
            return when (op) {
                "SCMP_CMP_NE" -> NativeH.SCMP_CMP_NE()
                "SCMP_CMP_LT" -> NativeH.SCMP_CMP_LT()
                "SCMP_CMP_LE" -> NativeH.SCMP_CMP_LE()
                "SCMP_CMP_EQ" -> NativeH.SCMP_CMP_EQ()
                "SCMP_CMP_GE" -> NativeH.SCMP_CMP_GE()
                "SCMP_CMP_GT" -> NativeH.SCMP_CMP_GT()
                "SCMP_CMP_MASKED_EQ" -> NativeH.SCMP_CMP_MASKED_EQ()
                else -> 0
            }
        }

        /**
         * Count the total number of rules (name x action pairs) the spec will
         * install. Each entry in `syscalls` may cover several names, and every
         * name becomes an independent libseccomp rule.
         */
        private fun countSyscalls(syscalls: List<LinuxSyscall>): Int {
            var n = 0
            for (s in syscalls) {
                n += s.names?.size ?: 0
            }
            return n
        }

        /**
         * Install a raw BPF filter that returns ENOSYS for syscall numbers beyond
         * the native architecture's known range. This is the equivalent of runc's
         * patchbpf prepend. The filter is installed as a SECOND seccomp filter
         * (after the libseccomp one). Since the kernel picks the most restrictive
         * result when multiple filters exist, and ERRNO(ENOSYS) beats ALLOW, this
         * correctly upgrades "unknown syscall gets ALLOW" to ENOSYS. For syscalls
         * where the main filter returns something more restrictive than ERRNO
         * (KILL, TRAP), that still wins.
         */
        private fun installEnosysStub(
            arena: Arena,
            syscalls: List<LinuxSyscall>?,
            filterFlags: Int
        ) {
            val maxNr = findMaxSyscallNr(arena, syscalls)
            if (maxNr <= 0) {
                Logger.debug("patchbpf: no syscalls resolved, skipping ENOSYS stub")
                return
            }
            val threshold = maxNr + 1
            Logger.debug("patchbpf: ENOSYS stub for nr >= $threshold")

            // AUDIT_ARCH_* = EM_<arch> | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
            // aarch64: 0xC00000B7 (EM_AARCH64=183), x86_64: 0xC000003E (EM_X86_64=62)
            val auditArch = if (Constants.isAarch64()) 0xC00000B7L else 0xC000003EL
            // SECCOMP_RET_ERRNO(ENOSYS) = SECCOMP_RET_ERRNO_BASE | 38
            val retEnosys = 0x00050000 or 38
            // SECCOMP_RET_ALLOW
            val retAllow = 0x7FFF0000

            // BPF program: 6 instructions
            //  [0] LD_ABS  arch          (seccomp_data.arch at offset 4)
            //  [1] JEQ     auditArch 0 3 (if arch != native, skip to ALLOW)
            //  [2] LD_ABS  nr            (seccomp_data.nr at offset 0)
            //  [3] JGE     threshold 0 1 (if nr < threshold, skip to ALLOW)
            //  [4] RET     ERRNO|ENOSYS
            //  [5] RET     ALLOW
            val instCount = 6
            val instSize = 8 // struct sock_filter = 8 bytes
            val filter = arena.allocate(instCount.toLong() * instSize)
            // Helper to write one BPF instruction
            // struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }
            writeBpfInst(filter, 0, 0x20.toShort(), 0, 0, 4)                            // LD_ABS arch
            writeBpfInst(filter, 1, 0x15.toShort(), 0, 3, auditArch.toInt())             // JEQ native
            writeBpfInst(filter, 2, 0x20.toShort(), 0, 0, 0)                            // LD_ABS nr
            writeBpfInst(filter, 3, 0x35.toShort(), 0, 1, threshold)                    // JGE threshold
            writeBpfInst(filter, 4, 0x06.toShort(), 0, 0, retEnosys)                    // RET ENOSYS
            writeBpfInst(filter, 5, 0x06.toShort(), 0, 0, retAllow)                     // RET ALLOW

            // struct sock_fprog { unsigned short len; /*pad*/ struct sock_filter *filter; }
            // On 64-bit: 2 + 6(pad) + 8(pointer) = 16 bytes
            val prog = arena.allocate(16)
            prog.set(ValueLayout.JAVA_SHORT, 0L, instCount.toShort())
            prog.set(ValueLayout.ADDRESS, 8L, filter)

            // seccomp(SECCOMP_SET_MODE_FILTER=1, flags, &prog)
            // Always include TSYNC (flag 1) so the filter covers all JVM threads.
            val flags = filterFlags or 1 // SECCOMP_FILTER_FLAG_TSYNC = 1
            val rc = Libc.syscall(Constants.NR_seccomp, 1L, flags.toLong(), prog.address(), 0L, 0L)
            if (rc != 0L) {
                Logger.warn(
                    "patchbpf: seccomp(SET_MODE_FILTER) failed: ${Libc.strerror(Libc.errno())}"
                )
            } else {
                Logger.debug("patchbpf: ENOSYS stub installed")
            }
        }

        private fun writeBpfInst(
            buf: MemorySegment, idx: Int, code: Short,
            jt: Byte, jf: Byte, k: Int
        ) {
            val off = idx * 8L
            buf.set(ValueLayout.JAVA_SHORT, off, code)
            buf.set(ValueLayout.JAVA_BYTE, off + 2, jt)
            buf.set(ValueLayout.JAVA_BYTE, off + 3, jf)
            buf.set(ValueLayout.JAVA_INT, off + 4, k)
        }

        /**
         * Find the highest native syscall number by probing libseccomp with known
         * syscall names (from the spec and from a list of recently-added syscalls).
         */
        private fun findMaxSyscallNr(
            arena: Arena,
            syscalls: List<LinuxSyscall>?
        ): Int {
            var max = 0
            // Probe spec-referenced syscalls.
            if (syscalls != null) {
                for (sc in syscalls) {
                    if (sc.names == null) continue
                    for (name in sc.names) {
                        val nr = NativeH.seccomp_syscall_resolve_name(arena.allocateFrom(name))
                        if (nr != NativeH.__NR_SCMP_ERROR() && nr > 0 && nr > max) max = nr
                    }
                }
            }
            // Probe well-known high-numbered syscalls to find the native arch's max.
            // Listed from newest to oldest so the first match gives the highest number.
            val probes = arrayOf(
                "removexattrat", "listxattrat", "getxattrat", "setxattrat",
                "mseal", "lsm_list_modules", "lsm_set_self_attr", "lsm_get_self_attr",
                "listmount", "statmount", "futex_requeue", "futex_wait", "futex_wake",
                "fchmodat2", "cachestat", "set_mempolicy_home_node", "process_mrelease",
                "futex_waitv", "epoll_pwait2", "mount_setattr", "openat2", "pidfd_getfd",
                "close_range", "io_uring_setup", "pidfd_send_signal", "io_uring_enter",
                "rseq", "pkey_free", "pkey_alloc", "pkey_mprotect", "statx",
                "copy_file_range", "preadv2", "memfd_create", "getrandom", "membarrier",
                "execveat", "userfaultfd", "seccomp", "sched_setattr", "renameat2",
                "kcmp", "finit_module", "process_vm_writev", "process_vm_readv",
            )
            for (name in probes) {
                val nr = NativeH.seccomp_syscall_resolve_name(arena.allocateFrom(name))
                if (nr != NativeH.__NR_SCMP_ERROR() && nr > 0 && nr > max) max = nr
            }
            if (max < 100) max = 450 // safe fallback
            return max
        }

        private fun actionToken(action: String?, errnoRet: Long?): Int {
            // ERRNO and TRACE encode the extra data in the low 16 bits of the
            // action word. Any value that doesn't fit there is a spec bug — silently
            // masking it would turn EINVAL(22) into … well, still 22, but ENOSYS
            // (38 with a bit 16 set) into 38 with the top bit dropped. Refuse
            // rather than mislead.
            // OCI spec: when errnoRet is not set for SCMP_ACT_ERRNO, default to
            // EPERM (1). SCMP_ACT_ERRNO(0) would make the syscall succeed silently.
            val errno = errnoRet?.toInt() ?: 1
            if ((action == "SCMP_ACT_ERRNO" || action == "SCMP_ACT_TRACE")
                && (errno < 0 || errno > 0xffff)
            ) {
                throw IllegalArgumentException(
                    "seccomp: errnoRet $errno out of range for $action" +
                    " (must fit in the low 16 bits)"
                )
            }
            // libseccomp action codes from seccomp.h
            return when (action ?: "SCMP_ACT_ALLOW") {
                "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD" -> NativeH.SCMP_ACT_KILL_THREAD()
                "SCMP_ACT_KILL_PROCESS" -> NativeH.SCMP_ACT_KILL_PROCESS()
                "SCMP_ACT_TRAP" -> NativeH.SCMP_ACT_TRAP()
                // ERRNO and TRACE carry their data in the low 16 bits. The macros
                // are function-like, so seccomp.h exposes their base values through
                // an enum that jextract can emit.
                "SCMP_ACT_ERRNO" -> NativeH.TAKOYAKI_SCMP_ACT_ERRNO_BASE() or (errno and 0xffff)
                "SCMP_ACT_TRACE" -> NativeH.TAKOYAKI_SCMP_ACT_TRACE_BASE() or (errno and 0xffff)
                "SCMP_ACT_LOG" -> NativeH.SCMP_ACT_LOG()
                "SCMP_ACT_ALLOW" -> NativeH.SCMP_ACT_ALLOW()
                "SCMP_ACT_NOTIFY" -> ACT_NOTIFY
                else -> NativeH.SCMP_ACT_ALLOW()
            }
        }
    }
}
