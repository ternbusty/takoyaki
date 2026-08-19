package com.ternbusty.takoyaki.capability;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Capability {
    private Capability() {}

    private static final String[] NAMES = {
            "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
            "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
            "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
            "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE"
    };

    /** Highest cap id we know about — the ids are the NAMES array indices. */
    private static final int LAST_CAP = NAMES.length - 1;

    private static final Map<String, Integer> CAPS = new HashMap<>();
    static {
        for (int i = 0; i < NAMES.length; i++) CAPS.put(NAMES[i], i);
    }

    public static int idOf(String name) {
        Integer v = CAPS.get(name);
        return v == null ? -1 : v;
    }

    public static void setKeepCaps() {
        if (Libc.prctl(Constants.PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
            Logger.warn("prctl(PR_SET_KEEPCAPS,1) failed: " + Libc.strerror(Libc.errno()));
        }
    }

    public static void clearKeepCaps() {
        if (Libc.prctl(Constants.PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0) {
            Logger.warn("prctl(PR_SET_KEEPCAPS,0) failed: " + Libc.strerror(Libc.errno()));
        }
    }

    public static void applyBoundingSet(Spec.LinuxCapabilities caps) {
        if (caps == null || caps.bounding == null) return;
        Set<Integer> keep = parseSet(caps.bounding);
        for (int i = 0; i <= LAST_CAP; i++) {
            if (!keep.contains(i)) {
                Libc.prctl(Constants.PR_CAPBSET_DROP, i, 0, 0, 0);
            }
        }
        Logger.debug("bounding set applied (" + keep.size() + " kept)");
    }

    public static void applyFinalSets(Spec.LinuxCapabilities caps) {
        if (caps == null) return;
        long eff = mask(caps.effective);
        long per = mask(caps.permitted);
        long inh = mask(caps.inheritable);
        capset(eff, per, inh);

        if (caps.ambient != null) {
            Libc.prctl(Constants.PR_CAP_AMBIENT, Constants.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
            // The kernel refuses PR_CAP_AMBIENT_RAISE unless the cap is in
            // BOTH permitted AND inheritable. Silently swallowing the EPERM
            // that would result from a spec that says "ambient: [CAP_X]"
            // without also listing X in permitted+inheritable hides the
            // config mistake — the user asked for X to be preserved across
            // execve, and it silently isn't. Check up front and log which
            // set is missing.
            for (String name : caps.ambient) {
                int id = idOf(name);
                if (id < 0) continue;
                if (Libc.prctl(Constants.PR_CAP_AMBIENT, Constants.PR_CAP_AMBIENT_RAISE, id, 0, 0) != 0) {
                    // runc compat: print the same warning logrus emits.
                    String rawErr = Libc.strerror(Libc.errno());
                    String errMsg = rawErr.isEmpty() ? rawErr
                            : Character.toLowerCase(rawErr.charAt(0)) + rawErr.substring(1);
                    System.err.println("can't raise ambient capability " + name + ": " + errMsg);
                }
            }
        }
    }

    private static Set<Integer> parseSet(List<String> names) {
        Set<Integer> s = new HashSet<>();
        if (names == null) return s;
        for (String n : names) {
            int id = idOf(n);
            if (id >= 0) {
                s.add(id);
            } else {
                Logger.warn("unknown capability name: " + n);
            }
        }
        return s;
    }

    private static long mask(List<String> names) {
        long m = 0L;
        for (int id : parseSet(names)) m |= (1L << id);
        return m;
    }

    private static void capset(long eff, long per, long inh) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment header = arena.allocate(8);
            header.set(ValueLayout.JAVA_INT, 0, Constants.LINUX_CAPABILITY_VERSION_3);
            header.set(ValueLayout.JAVA_INT, 4, 0);

            MemorySegment data = arena.allocate(12 * 2);
            data.set(ValueLayout.JAVA_INT, 0, (int) (eff & 0xffffffffL));
            data.set(ValueLayout.JAVA_INT, 4, (int) (per & 0xffffffffL));
            data.set(ValueLayout.JAVA_INT, 8, (int) (inh & 0xffffffffL));
            data.set(ValueLayout.JAVA_INT, 12, (int) ((eff >>> 32) & 0xffffffffL));
            data.set(ValueLayout.JAVA_INT, 16, (int) ((per >>> 32) & 0xffffffffL));
            data.set(ValueLayout.JAVA_INT, 20, (int) ((inh >>> 32) & 0xffffffffL));

            long rc = Libc.syscall(Constants.NR_capset,
                    header.address(), data.address(), 0L, 0L, 0L);
            if (rc != 0) {
                Logger.warn("capset failed: " + Libc.strerror(Libc.errno()));
            } else {
                Logger.debug("capset eff=0x" + Long.toHexString(eff) + " per=0x" + Long.toHexString(per));
            }
        }
    }
}
