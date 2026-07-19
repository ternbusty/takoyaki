package com.ternbusty.takoyaki.seccomp;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.State;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

public final class Seccomp {
    private Seccomp() {}

    private static final Linker LINKER = Linker.nativeLinker();
    private static volatile SymbolLookup libseccomp;
    private static volatile MethodHandle SECCOMP_INIT;
    private static volatile MethodHandle SECCOMP_RELEASE;
    private static volatile MethodHandle SECCOMP_RULE_ADD;
    private static volatile MethodHandle SECCOMP_RULE_ADD_ARRAY;
    private static volatile MethodHandle SECCOMP_LOAD;
    private static volatile MethodHandle SECCOMP_NOTIFY_FD;
    private static volatile MethodHandle SECCOMP_SYSCALL_RESOLVE_NAME;
    private static volatile MethodHandle SECCOMP_ARCH_ADD;
    private static volatile MethodHandle SECCOMP_ARCH_REMOVE;
    private static volatile MethodHandle SECCOMP_ARCH_RESOLVE_NAME;
    private static volatile MethodHandle SECCOMP_ATTR_SET;

    private static synchronized boolean ensureLoaded() {
        if (libseccomp != null) return true;
        try {
            SymbolLookup s = libraryLookupWithFallback();
            libseccomp = s;
            SECCOMP_INIT = LINKER.downcallHandle(s.find("seccomp_init").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
            SECCOMP_RELEASE = LINKER.downcallHandle(s.find("seccomp_release").orElseThrow(),
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
            SECCOMP_RULE_ADD = LINKER.downcallHandle(s.find("seccomp_rule_add").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT));
            // int seccomp_rule_add_array(scmp_filter_ctx, uint32_t action, int syscall,
            //                            unsigned int arg_cnt, const struct scmp_arg_cmp *arg_array);
            SECCOMP_RULE_ADD_ARRAY = LINKER.downcallHandle(
                    s.find("seccomp_rule_add_array").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            SECCOMP_LOAD = LINKER.downcallHandle(s.find("seccomp_load").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            SECCOMP_NOTIFY_FD = LINKER.downcallHandle(s.find("seccomp_notify_fd").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            SECCOMP_SYSCALL_RESOLVE_NAME = LINKER.downcallHandle(s.find("seccomp_syscall_resolve_name").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            SECCOMP_ARCH_ADD = LINKER.downcallHandle(s.find("seccomp_arch_add").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
            SECCOMP_ARCH_REMOVE = LINKER.downcallHandle(s.find("seccomp_arch_remove").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
            SECCOMP_ARCH_RESOLVE_NAME = LINKER.downcallHandle(s.find("seccomp_arch_resolve_name").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            SECCOMP_ATTR_SET = LINKER.downcallHandle(s.find("seccomp_attr_set").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
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
            MemorySegment ctx = (MemorySegment) SECCOMP_INIT.invoke(defaultAction);
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
                int SCMP_FLTATR_CTL_NNP = 3;
                int SCMP_FLTATR_CTL_TSYNC = 4;
                int SCMP_FLTATR_CTL_LOG = 5;
                int SCMP_FLTATR_CTL_SSB = 6;
                SECCOMP_ATTR_SET.invoke(ctx, SCMP_FLTATR_CTL_NNP, 0L);

                // Translate the OCI spec's filter flags into the libseccomp
                // attributes that back them. Unknown flags are warned about
                // rather than ignored so the caller sees the mismatch.
                if (sec.flags != null) {
                    for (String flag : sec.flags) {
                        switch (flag) {
                            case "SECCOMP_FILTER_FLAG_TSYNC" ->
                                    SECCOMP_ATTR_SET.invoke(ctx, SCMP_FLTATR_CTL_TSYNC, 1L);
                            case "SECCOMP_FILTER_FLAG_LOG" ->
                                    SECCOMP_ATTR_SET.invoke(ctx, SCMP_FLTATR_CTL_LOG, 1L);
                            case "SECCOMP_FILTER_FLAG_SPEC_ALLOW" ->
                                    SECCOMP_ATTR_SET.invoke(ctx, SCMP_FLTATR_CTL_SSB, 1L);
                            default -> Logger.warn("unknown seccomp filter flag: " + flag);
                        }
                    }
                }

                // architectures - libseccomp wants lowercase, no SCMP_ARCH_ prefix
                if (sec.architectures != null) {
                    for (String archName : sec.architectures) {
                        String n = archName;
                        if (n.startsWith("SCMP_ARCH_")) n = n.substring("SCMP_ARCH_".length());
                        n = n.toLowerCase();
                        MemorySegment nameSeg = arena.allocateFrom(n);
                        int token = (int) SECCOMP_ARCH_RESOLVE_NAME.invoke(nameSeg);
                        if (token == 0) {
                            Logger.warn("unknown seccomp arch: " + archName);
                            continue;
                        }
                        SECCOMP_ARCH_ADD.invoke(ctx, token);
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
                            int nr = (int) SECCOMP_SYSCALL_RESOLVE_NAME.invoke(nameSeg);
                            if (nr == 0x7fffffff /* __NR_SCMP_ERROR */) {
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
                                rc = (int) SECCOMP_RULE_ADD_ARRAY.invoke(
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

                int loadRc = (int) SECCOMP_LOAD.invoke(ctx);
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
                    int notifyFd = (int) SECCOMP_NOTIFY_FD.invoke(ctx);
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
                SECCOMP_RELEASE.invoke(ctx);
            }
        } catch (Throwable t) {
            Logger.error("seccomp apply error: " + t.getMessage());
        }
    }

    /**
     * Encode SeccompArg entries into struct scmp_arg_cmp[] and call seccomp_rule_add_array.
     * struct scmp_arg_cmp layout: unsigned int arg; enum scmp_compare op; uint64_t datum_a; uint64_t datum_b;
     * Padding bumps the struct to 24 bytes on aarch64/x86_64.
     */
    private static int addRuleWithArgs(Arena arena, MemorySegment ctx, int action, int nr,
                                       java.util.List<Spec.SeccompArg> args) throws Throwable {
        int n = args.size();
        MemorySegment arr = arena.allocate(24L * n);
        for (int i = 0; i < n; i++) {
            Spec.SeccompArg a = args.get(i);
            long base = 24L * i;
            arr.set(ValueLayout.JAVA_INT, base, a.index);
            arr.set(ValueLayout.JAVA_INT, base + 4, mapCompare(a.op));
            arr.set(ValueLayout.JAVA_LONG, base + 8, a.value);
            arr.set(ValueLayout.JAVA_LONG, base + 16,
                    a.valueTwo == null ? 0 : a.valueTwo);
        }
        return (int) SECCOMP_RULE_ADD_ARRAY.invoke(ctx, action, nr, n, arr);
    }

    private static int mapCompare(String op) {
        if (op == null) return 0;
        return switch (op) {
            case "SCMP_CMP_NE" -> 1;
            case "SCMP_CMP_LT" -> 2;
            case "SCMP_CMP_LE" -> 3;
            case "SCMP_CMP_EQ" -> 4;
            case "SCMP_CMP_GE" -> 5;
            case "SCMP_CMP_GT" -> 6;
            case "SCMP_CMP_MASKED_EQ" -> 7;
            default -> 0;
        };
    }

    // libseccomp action code for SCMP_ACT_NOTIFY, from seccomp.h.
    private static final int ACT_NOTIFY = 0x7fc00000;

    private static int actionToken(String action, Long errnoRet) {
        // ERRNO and TRACE encode the extra data in the low 16 bits of the
        // action word. Any value that doesn't fit there is a spec bug — silently
        // masking it would turn EINVAL(22) into … well, still 22, but ENOSYS
        // (38 with a bit 16 set) into 38 with the top bit dropped. Refuse
        // rather than mislead.
        int errno = errnoRet == null ? 0 : errnoRet.intValue();
        if (("SCMP_ACT_ERRNO".equals(action) || "SCMP_ACT_TRACE".equals(action))
                && (errno < 0 || errno > 0xffff)) {
            throw new IllegalArgumentException(
                    "seccomp: errnoRet " + errno + " out of range for " + action
                            + " (must fit in the low 16 bits)");
        }
        // libseccomp action codes from seccomp.h
        return switch (action == null ? "SCMP_ACT_ALLOW" : action) {
            case "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD" -> 0x00000000;
            case "SCMP_ACT_KILL_PROCESS" -> 0x80000000;
            case "SCMP_ACT_TRAP" -> 0x00030000;
            case "SCMP_ACT_ERRNO" -> 0x00050000 | (errno & 0xffff);
            case "SCMP_ACT_TRACE" -> 0x7ff00000 | (errno & 0xffff);
            case "SCMP_ACT_LOG" -> 0x7ffc0000;
            case "SCMP_ACT_ALLOW" -> 0x7fff0000;
            case "SCMP_ACT_NOTIFY" -> ACT_NOTIFY;
            default -> 0x7fff0000;
        };
    }

    private static SymbolLookup libraryLookupWithFallback() {
        String[] candidates = {
                "libseccomp.so.2",
                "/usr/lib/aarch64-linux-gnu/libseccomp.so.2",
                "/usr/lib/x86_64-linux-gnu/libseccomp.so.2",
                "/lib/aarch64-linux-gnu/libseccomp.so.2",
                "/lib/x86_64-linux-gnu/libseccomp.so.2",
        };
        Throwable last = null;
        for (String c : candidates) {
            try {
                return SymbolLookup.libraryLookup(c, Arena.global());
            } catch (Throwable t) { last = t; }
        }
        throw new RuntimeException("libseccomp.so.2 not loadable", last);
    }
}
