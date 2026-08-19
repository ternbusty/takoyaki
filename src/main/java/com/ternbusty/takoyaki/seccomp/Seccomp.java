package com.ternbusty.takoyaki.seccomp;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.libseccomp.SeccompH;
import com.ternbusty.takoyaki.syscall.libseccomp.scmp_arg_cmp;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

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
                            default -> Logger.warn("unknown seccomp filter flag: " + flag);
                        }
                    }
                } else {
                    // No flags field in the spec: default to SPEC_ALLOW.
                    SeccompH.seccomp_attr_set(ctx, SeccompH.SCMP_FLTATR_CTL_SSB(), 1);
                    filterFlagsValue = 4;
                }
                Logger.debug("seccomp filter flags: " + filterFlagsValue);

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
                                    "seccomp: SCMP_ACT_NOTIFY on write(2) is not"
                                            + " permitted (would deadlock the notifier)");
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
                            int rc;
                            if (sc.args == null || sc.args.isEmpty()) {
                                // Use seccomp_rule_add_array even with zero args. The
                                // variadic seccomp_rule_add silently mis-loads the
                                // notify state under Panama FFM (seccomp_notify_fd
                                // returns -EFAULT afterwards), while the non-variadic
                                // array variant works.
                                rc = SeccompH.seccomp_rule_add_array(
                                        ctx, action, nr, 0, MemorySegment.NULL);
                            } else {
                                rc = addRuleWithArgs(arena, ctx, action, nr, sc.args);
                            }
                            if (rc != 0) {
                                Logger.debug("rule_add " + name + " failed: " + rc);
                            }
                        }
                    }
                }

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
        } catch (Throwable t) {
            Logger.error("seccomp apply error: " + t.getMessage());
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
