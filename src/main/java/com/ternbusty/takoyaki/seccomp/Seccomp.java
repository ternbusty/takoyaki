package com.ternbusty.takoyaki.seccomp;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.libseccomp.SeccompH;
import com.ternbusty.takoyaki.syscall.libseccomp.scmp_arg_cmp;

import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * libseccomp facade over the jextract-generated {@link SeccompH} bindings. The
 * plumbing moved from hand-written FFM downcalls to generated ones; the filter
 * semantics are unchanged.
 */
public final class Seccomp {
    private Seccomp() {}

    /**
     * Force libseccomp to be dlopen'd now. Must run before pivot_root cuts the
     * process off from the host filesystem: the container rootfs does not ship
     * libseccomp and the C bootstrap only preloads libc/libm/libdl/libpthread/
     * librt. Touching any SeccompH entry point triggers its class initializer,
     * whose {@code libraryLookup("libseccomp.so.2")} loads the library.
     */
    public static boolean preload() {
        return ensureLoaded();
    }

    private static synchronized boolean ensureLoaded() {
        try (Arena arena = Arena.ofConfined()) {
            // Harmless call — resolves a syscall name — that forces SeccompH's
            // <clinit> (the library load) to run and surfaces a load failure.
            SeccompH.seccomp_syscall_resolve_name(arena.allocateFrom("read"));
            return true;
        } catch (Throwable t) {
            Logger.warn("libseccomp not loadable: " + t.getMessage());
            return false;
        }
    }

    /**
     * @param state          used only when SCMP_ACT_NOTIFY rules are present and
     *                       {@code sec.listenerPath} is set; serialized as the state
     *                       JSON sent to the listener.
     * @param preConnectedFd host-side pre-connected listener socket fd, or -1 when
     *                       absent (the listener path must then be reachable from
     *                       here, which it usually isn't post-pivot).
     */
    public static void apply(Spec.LinuxSeccomp sec, State state, int preConnectedFd) {
        if (sec == null) return;
        if (!ensureLoaded()) {
            Logger.error("libseccomp.so.2 not found, cannot apply seccomp");
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            int defaultAction = actionToken(sec.defaultAction, sec.defaultErrnoRet);
            MemorySegment ctx = SeccompH.seccomp_init(defaultAction);
            if (ctx == null || ctx.address() == 0) {
                Logger.error("seccomp_init returned NULL");
                return;
            }
            try {
                // libseccomp defaults SCMP_FLTATR_CTL_NNP to 1, which makes
                // seccomp_load() unconditionally call prctl(PR_SET_NO_NEW_PRIVS, 1).
                // That breaks specs that set noNewPrivileges=false and would also
                // mask cases where the runtime is supposed to be in charge of NNP.
                // Disable libseccomp's auto-NNP — the runtime sets NNP earlier
                // based on spec.process.noNewPrivileges.
                SeccompH.seccomp_attr_set(ctx, SeccompH.SCMP_FLTATR_CTL_NNP(), 0);

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
                int filterFlagsValue = 0;
                if (sec.flags != null) {
                    for (String flag : sec.flags) {
                        switch (flag) {
                            case "SECCOMP_FILTER_FLAG_TSYNC" -> {
                                SeccompH.seccomp_attr_set(ctx, SeccompH.SCMP_FLTATR_CTL_TSYNC(), 1);
                                // TSYNC contributes 0 to the kernel flags
                            }
                            case "SECCOMP_FILTER_FLAG_LOG" -> {
                                SeccompH.seccomp_attr_set(ctx, SeccompH.SCMP_FLTATR_CTL_LOG(), 1);
                                filterFlagsValue |= 2;
                            }
                            case "SECCOMP_FILTER_FLAG_SPEC_ALLOW" -> {
                                SeccompH.seccomp_attr_set(ctx, SeccompH.SCMP_FLTATR_CTL_SSB(), 1);
                                filterFlagsValue |= 4;
                            }
                            case "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV" -> {
                                // SCMP_FLTATR_CTL_WAITKILL = 10 (libseccomp 2.5.4+)
                                int rc = SeccompH.seccomp_attr_set(ctx, 10, 1);
                                if (rc != 0) {
                                    Logger.warn("seccomp_attr_set(WAITKILL) failed: " + rc
                                            + " (requires libseccomp >= 2.5.4 and kernel >= 5.19)");
                                } else {
                                    filterFlagsValue |= 0x20;
                                }
                            }
                            default -> Logger.warn("unknown seccomp filter flag: " + flag);
                        }
                    }
                } else {
                    // No flags field in the spec: default to SPEC_ALLOW.
                    SeccompH.seccomp_attr_set(ctx, SeccompH.SCMP_FLTATR_CTL_SSB(), 1);
                    filterFlagsValue = 4;
                }
                // Ask libseccomp to compile the rule set into a binary tree
                // once it gets large enough for the linear match to hurt.
                // Docker's default profile has hundreds of syscalls; without
                // this every allowed syscall pays for walking the whole list.
                // runc uses the same 32-rule threshold.
                if (sec.syscalls != null && countSyscalls(sec.syscalls) > 32) {
                    SeccompH.seccomp_attr_set(ctx, SeccompH.SCMP_FLTATR_CTL_OPTIMIZE(), 2);
                }

                // architectures - libseccomp wants lowercase, no SCMP_ARCH_ prefix
                if (sec.architectures != null) {
                    for (String archName : sec.architectures) {
                        String n = archName;
                        if (n.startsWith("SCMP_ARCH_")) n = n.substring("SCMP_ARCH_".length());
                        n = n.toLowerCase();
                        MemorySegment nameSeg = arena.allocateFrom(n);
                        int token = SeccompH.seccomp_arch_resolve_name(nameSeg);
                        if (token == 0) {
                            Logger.warn("unknown seccomp arch: " + archName);
                            continue;
                        }
                        SeccompH.seccomp_arch_add(ctx, token);
                    }
                }

                boolean hasNotify = false;
                if (sec.syscalls != null) {
                    for (Spec.LinuxSyscall sc : sec.syscalls) {
                        int action = actionToken(sc.action, sc.errnoRet);
                        if (action == ACT_NOTIFY) hasNotify = true;
                        if (sc.names == null) continue;
                        // SCMP_ACT_NOTIFY on write(2) is a deadlock trap: the
                        // supervisor process reads the notify fd, and its
                        // response typically involves writing back through the
                        // same syscall the container just called. runc and
                        // youki both refuse this combination up front.
                        if ("SCMP_ACT_NOTIFY".equals(sc.action)
                                && sc.names.contains("write")) {
                            throw new RuntimeException(
                                    "SCMP_ACT_NOTIFY cannot be used for the write syscall");
                        }
                        for (String name : sc.names) {
                            MemorySegment nameSeg = arena.allocateFrom(name);
                            int nr = SeccompH.seccomp_syscall_resolve_name(nameSeg);
                            if (nr == SeccompH.__NR_SCMP_ERROR()) {
                                Logger.debug("syscall " + name + " unknown to libseccomp, skipping");
                                continue;
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
                            if (sc.args == null || sc.args.isEmpty()) {
                                // Use seccomp_rule_add_array even with zero args. The
                                // variadic seccomp_rule_add silently mis-loads the
                                // notify state under Panama FFM (seccomp_notify_fd
                                // returns -EFAULT afterwards), while the non-variadic
                                // array variant works.
                                int rc = SeccompH.seccomp_rule_add_array(
                                        ctx, action, nr, 0, MemorySegment.NULL);
                                if (rc != 0) {
                                    Logger.debug("rule_add " + name + " failed: " + rc);
                                }
                            } else {
                                // runc compat: when multiple args reference the same
                                // index, they form an OR (any match triggers the
                                // action). libseccomp treats all args in a single
                                // rule_add as AND. Split into groups where each group
                                // has at most one condition per arg index.
                                addRulesWithOrSplit(arena, ctx, action, nr, sc.args);
                            }
                        }
                    }
                }

                // Log the effective filter flags. When SCMP_ACT_NOTIFY rules
                // are present, libseccomp internally adds NEW_LISTENER (0x08)
                // to the kernel flags passed to seccomp(2). Include it in the
                // reported value so the debug output matches runc.
                int reportedFlags = filterFlagsValue;
                if (hasNotify) {
                    reportedFlags |= 0x08; // SECCOMP_FILTER_FLAG_NEW_LISTENER
                }
                Logger.debug("seccomp filter flags: " + reportedFlags);

                int loadRc = SeccompH.seccomp_load(ctx);
                if (loadRc != 0) {
                    // Silently returning here would let the container come up
                    // with no filter at all, which is worse than failing to
                    // start — the user requested a seccomp policy and the
                    // runtime is now serving one that does not exist. Bail so
                    // the surrounding init aborts.
                    throw new RuntimeException("seccomp_load failed: " + loadRc);
                }
                Logger.info("seccomp filter loaded");

                // runc compat (patchbpf): install a second BPF filter that
                // returns ENOSYS for syscall numbers beyond the native arch's
                // known range. Without this stub, unknown/future syscalls hit
                // the libseccomp default action (typically ERRNO+EPERM) instead
                // of the expected ENOSYS.
                installEnosysStub(arena, sec.syscalls, filterFlagsValue);

                // If the spec declared any SCMP_ACT_NOTIFY rules, pull the notify fd
                // out of the loaded context. We don't manage a listener — that's the
                // caller's responsibility — but make the fd reachable via env var.
                if (hasNotify) {
                    Logger.debug("seccomp ctx address=0x"
                            + Long.toHexString(ctx.address())
                            + " (about to call seccomp_notify_fd)");
                    int notifyFd = SeccompH.seccomp_notify_fd(ctx);
                    if (notifyFd < 0) {
                        Logger.warn("seccomp_notify_fd returned " + notifyFd);
                    } else if (sec.listenerPath == null || sec.listenerPath.isEmpty()) {
                        Logger.warn("SCMP_ACT_NOTIFY rules present but no listenerPath; "
                                + "leaving notify fd=" + notifyFd
                                + " unforwarded — matching syscalls will block forever");
                    } else {
                        SeccompListener.forward(sec.listenerPath, state,
                                sec.listenerMetadata, notifyFd, preConnectedFd);
                        // Close our copy; the listener has its own dup via SCM_RIGHTS.
                        com.ternbusty.takoyaki.syscall.PosixIO.close(notifyFd);
                    }
                }
            } finally {
                SeccompH.seccomp_release(ctx);
            }
        } catch (RuntimeException e) {
            // Rethrow runtime errors (validation failures like write+NOTIFY,
            // seccomp_load failures) so the caller can abort.
            Logger.error("seccomp apply error: " + e.getMessage());
            throw e;
        } catch (Throwable t) {
            Logger.error("seccomp apply error: " + t.getMessage());
            throw new RuntimeException(t);
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
    private static void addRulesWithOrSplit(Arena arena, MemorySegment ctx, int action, int nr,
                                             java.util.List<Spec.SeccompArg> args) {
        // Group args by index. If all indices are unique, we can use a single rule.
        java.util.Map<Integer, java.util.List<Spec.SeccompArg>> byIndex = new java.util.LinkedHashMap<>();
        for (Spec.SeccompArg a : args) {
            byIndex.computeIfAbsent(a.index, k -> new java.util.ArrayList<>()).add(a);
        }
        boolean hasDuplicateIndex = byIndex.values().stream().anyMatch(v -> v.size() > 1);
        if (!hasDuplicateIndex) {
            // Simple case: all unique indices, single AND rule.
            int rc = addRuleWithArgs(arena, ctx, action, nr, args);
            if (rc != 0) Logger.debug("rule_add failed: " + rc);
            return;
        }
        // Generate the Cartesian product of per-index arg groups.
        // Each combination becomes one rule_add call.
        java.util.List<java.util.List<Spec.SeccompArg>> groups = new java.util.ArrayList<>(byIndex.values());
        java.util.List<java.util.List<Spec.SeccompArg>> combos = new java.util.ArrayList<>();
        combos.add(new java.util.ArrayList<>());
        for (java.util.List<Spec.SeccompArg> group : groups) {
            java.util.List<java.util.List<Spec.SeccompArg>> next = new java.util.ArrayList<>();
            for (java.util.List<Spec.SeccompArg> prefix : combos) {
                for (Spec.SeccompArg a : group) {
                    java.util.List<Spec.SeccompArg> combo = new java.util.ArrayList<>(prefix);
                    combo.add(a);
                    next.add(combo);
                }
            }
            combos = next;
        }
        for (java.util.List<Spec.SeccompArg> combo : combos) {
            int rc = addRuleWithArgs(arena, ctx, action, nr, combo);
            if (rc != 0) Logger.debug("rule_add (OR split) failed: " + rc);
        }
    }

    /**
     * Encode SeccompArg entries into struct scmp_arg_cmp[] and call seccomp_rule_add_array.
     * struct scmp_arg_cmp layout: unsigned int arg; enum scmp_compare op; uint64_t datum_a; uint64_t datum_b.
     * Offsets come from the jextract-generated {@link scmp_arg_cmp} (header-derived), not a
     * hand-computed stride.
     */
    private static int addRuleWithArgs(Arena arena, MemorySegment ctx, int action, int nr,
                                       java.util.List<Spec.SeccompArg> args) {
        int n = args.size();
        MemorySegment arr = scmp_arg_cmp.allocateArray(n, arena);
        for (int i = 0; i < n; i++) {
            Spec.SeccompArg a = args.get(i);
            MemorySegment e = scmp_arg_cmp.asSlice(arr, i);
            scmp_arg_cmp.arg(e, a.index);
            scmp_arg_cmp.op(e, mapCompare(a.op));
            scmp_arg_cmp.datum_a(e, a.value);
            scmp_arg_cmp.datum_b(e, a.valueTwo == null ? 0 : a.valueTwo);
        }
        return SeccompH.seccomp_rule_add_array(ctx, action, nr, n, arr);
    }

    private static int mapCompare(String op) {
        if (op == null) return 0;
        return switch (op) {
            case "SCMP_CMP_NE" -> SeccompH.SCMP_CMP_NE();
            case "SCMP_CMP_LT" -> SeccompH.SCMP_CMP_LT();
            case "SCMP_CMP_LE" -> SeccompH.SCMP_CMP_LE();
            case "SCMP_CMP_EQ" -> SeccompH.SCMP_CMP_EQ();
            case "SCMP_CMP_GE" -> SeccompH.SCMP_CMP_GE();
            case "SCMP_CMP_GT" -> SeccompH.SCMP_CMP_GT();
            case "SCMP_CMP_MASKED_EQ" -> SeccompH.SCMP_CMP_MASKED_EQ();
            default -> 0;
        };
    }

    // libseccomp action code for SCMP_ACT_NOTIFY, from seccomp.h.
    private static final int ACT_NOTIFY = SeccompH.SCMP_ACT_NOTIFY();

    /**
     * Count the total number of rules (name × action pairs) the spec will
     * install. Each entry in `syscalls` may cover several names, and every
     * name becomes an independent libseccomp rule.
     */
    private static int countSyscalls(java.util.List<Spec.LinuxSyscall> syscalls) {
        int n = 0;
        for (Spec.LinuxSyscall s : syscalls) {
            if (s.names != null) n += s.names.size();
        }
        return n;
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
    private static void installEnosysStub(Arena arena,
                                           java.util.List<Spec.LinuxSyscall> syscalls,
                                           int filterFlags) {
        int maxNr = findMaxSyscallNr(arena, syscalls);
        if (maxNr <= 0) {
            Logger.debug("patchbpf: no syscalls resolved, skipping ENOSYS stub");
            return;
        }
        int threshold = maxNr + 1;
        Logger.debug("patchbpf: ENOSYS stub for nr >= " + threshold);

        // AUDIT_ARCH_* = EM_<arch> | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
        // aarch64: 0xC00000B7 (EM_AARCH64=183), x86_64: 0xC000003E (EM_X86_64=62)
        long auditArch = Constants.isAarch64() ? 0xC00000B7L : 0xC000003EL;
        // SECCOMP_RET_ERRNO(ENOSYS) = SECCOMP_RET_ERRNO_BASE | 38
        int retEnosys = 0x00050000 | 38;
        // SECCOMP_RET_ALLOW
        int retAllow = 0x7FFF0000;

        // BPF program: 6 instructions
        //  [0] LD_ABS  arch          (seccomp_data.arch at offset 4)
        //  [1] JEQ     auditArch 0 3 (if arch != native, skip to ALLOW)
        //  [2] LD_ABS  nr            (seccomp_data.nr at offset 0)
        //  [3] JGE     threshold 0 1 (if nr < threshold, skip to ALLOW)
        //  [4] RET     ERRNO|ENOSYS
        //  [5] RET     ALLOW
        int instCount = 6;
        int instSize = 8; // struct sock_filter = 8 bytes
        MemorySegment filter = arena.allocate(instCount * instSize);
        // Helper to write one BPF instruction
        // struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }
        writeBpfInst(filter, 0, (short) 0x20, (byte) 0, (byte) 0, 4);                     // LD_ABS arch
        writeBpfInst(filter, 1, (short) 0x15, (byte) 0, (byte) 3, (int) auditArch);       // JEQ native
        writeBpfInst(filter, 2, (short) 0x20, (byte) 0, (byte) 0, 0);                     // LD_ABS nr
        writeBpfInst(filter, 3, (short) 0x35, (byte) 0, (byte) 1, threshold);             // JGE threshold
        writeBpfInst(filter, 4, (short) 0x06, (byte) 0, (byte) 0, retEnosys);             // RET ENOSYS
        writeBpfInst(filter, 5, (short) 0x06, (byte) 0, (byte) 0, retAllow);              // RET ALLOW

        // struct sock_fprog { unsigned short len; /*pad*/ struct sock_filter *filter; }
        // On 64-bit: 2 + 6(pad) + 8(pointer) = 16 bytes
        MemorySegment prog = arena.allocate(16);
        prog.set(ValueLayout.JAVA_SHORT, 0, (short) instCount);
        prog.set(ValueLayout.ADDRESS, 8, filter);

        // seccomp(SECCOMP_SET_MODE_FILTER=1, flags, &prog)
        // Always include TSYNC (flag 1) so the filter covers all JVM threads.
        int flags = filterFlags | 1; // SECCOMP_FILTER_FLAG_TSYNC = 1
        long rc = Libc.syscall(Constants.NR_seccomp, 1, flags, prog.address(), 0, 0);
        if (rc != 0) {
            Logger.warn("patchbpf: seccomp(SET_MODE_FILTER) failed: "
                    + Libc.strerror(Libc.errno()));
        } else {
            Logger.debug("patchbpf: ENOSYS stub installed");
        }
    }

    private static void writeBpfInst(MemorySegment buf, int idx, short code,
                                      byte jt, byte jf, int k) {
        long off = idx * 8L;
        buf.set(ValueLayout.JAVA_SHORT, off, code);
        buf.set(ValueLayout.JAVA_BYTE, off + 2, jt);
        buf.set(ValueLayout.JAVA_BYTE, off + 3, jf);
        buf.set(ValueLayout.JAVA_INT, off + 4, k);
    }

    /**
     * Find the highest native syscall number by probing libseccomp with known
     * syscall names (from the spec and from a list of recently-added syscalls).
     */
    private static int findMaxSyscallNr(Arena arena,
                                         java.util.List<Spec.LinuxSyscall> syscalls) {
        int max = 0;
        // Probe spec-referenced syscalls.
        if (syscalls != null) {
            for (Spec.LinuxSyscall sc : syscalls) {
                if (sc.names == null) continue;
                for (String name : sc.names) {
                    int nr = SeccompH.seccomp_syscall_resolve_name(arena.allocateFrom(name));
                    if (nr != SeccompH.__NR_SCMP_ERROR() && nr > 0 && nr > max) max = nr;
                }
            }
        }
        // Probe well-known high-numbered syscalls to find the native arch's max.
        // Listed from newest to oldest so the first match gives the highest number.
        String[] probes = {
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
        };
        for (String name : probes) {
            int nr = SeccompH.seccomp_syscall_resolve_name(arena.allocateFrom(name));
            if (nr != SeccompH.__NR_SCMP_ERROR() && nr > 0 && nr > max) max = nr;
        }
        if (max < 100) max = 450; // safe fallback
        return max;
    }

    private static int actionToken(String action, Long errnoRet) {
        // ERRNO and TRACE encode the extra data in the low 16 bits of the
        // action word. Any value that doesn't fit there is a spec bug — silently
        // masking it would turn EINVAL(22) into … well, still 22, but ENOSYS
        // (38 with a bit 16 set) into 38 with the top bit dropped. Refuse
        // rather than mislead.
        // OCI spec: when errnoRet is not set for SCMP_ACT_ERRNO, default to
        // EPERM (1). SCMP_ACT_ERRNO(0) would make the syscall succeed silently.
        int errno = errnoRet == null ? 1 : errnoRet.intValue();
        if (("SCMP_ACT_ERRNO".equals(action) || "SCMP_ACT_TRACE".equals(action))
                && (errno < 0 || errno > 0xffff)) {
            throw new IllegalArgumentException(
                    "seccomp: errnoRet " + errno + " out of range for " + action
                            + " (must fit in the low 16 bits)");
        }
        // libseccomp action codes from seccomp.h
        return switch (action == null ? "SCMP_ACT_ALLOW" : action) {
            case "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD" -> SeccompH.SCMP_ACT_KILL_THREAD();
            case "SCMP_ACT_KILL_PROCESS" -> SeccompH.SCMP_ACT_KILL_PROCESS();
            case "SCMP_ACT_TRAP" -> SeccompH.SCMP_ACT_TRAP();
            // ERRNO and TRACE carry their data in the low 16 bits. The macros
            // are function-like, so seccomp.h exposes their base values through
            // an enum that jextract can emit.
            case "SCMP_ACT_ERRNO" -> SeccompH.TAKOYAKI_SCMP_ACT_ERRNO_BASE() | (errno & 0xffff);
            case "SCMP_ACT_TRACE" -> SeccompH.TAKOYAKI_SCMP_ACT_TRACE_BASE() | (errno & 0xffff);
            case "SCMP_ACT_LOG" -> SeccompH.SCMP_ACT_LOG();
            case "SCMP_ACT_ALLOW" -> SeccompH.SCMP_ACT_ALLOW();
            case "SCMP_ACT_NOTIFY" -> ACT_NOTIFY;
            default -> SeccompH.SCMP_ACT_ALLOW();
        };
    }
}
