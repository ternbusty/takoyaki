package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class Rlimit {
    private Rlimit() {}

    /** Apply all rlimits except the one named by {@code excludeType}. */
    public static void applyExcept(int pid, List<Spec.POSIXRlimit> rlimits, String excludeType) {
        if (rlimits == null || rlimits.isEmpty()) return;
        List<Spec.POSIXRlimit> filtered = rlimits.stream()
                .filter(r -> !excludeType.equals(r.type))
                .toList();
        apply(pid, filtered);
    }

    /** Apply only the rlimit named by {@code onlyType}. */
    public static void applyOnly(int pid, List<Spec.POSIXRlimit> rlimits, String onlyType) {
        if (rlimits == null || rlimits.isEmpty()) return;
        List<Spec.POSIXRlimit> filtered = rlimits.stream()
                .filter(r -> onlyType.equals(r.type))
                .toList();
        apply(pid, filtered);
    }

    public static void apply(int pid, List<Spec.POSIXRlimit> rlimits) {
        if (rlimits == null || rlimits.isEmpty()) return;
        Syscalls sc = SyscallHost.current();
        for (Spec.POSIXRlimit r : rlimits) {
            int resource = resourceId(r.type);
            if (resource < 0) {
                Logger.warn("unknown rlimit type: " + r.type);
                continue;
            }
            if (resource == Constants.RLIMIT_NOFILE) {
                applyNofile(sc, pid, r);
            } else {
                int rc = sc.prlimit64(pid, resource, r.soft, r.hard);
                if (rc != 0) {
                    Logger.warn("prlimit64 " + r.type + " failed: " + sc.strerror(sc.errno()));
                } else {
                    Logger.debug("rlimit " + r.type + " soft=" + r.soft + " hard=" + r.hard);
                }
            }
        }
    }

    /**
     * Special handling for RLIMIT_NOFILE: on Linux 5.11+, a privileged
     * process can set the hard limit above fs.nr_open by first raising the
     * hard limit to nr_open (which the kernel always allows), then raising
     * it beyond. This two-phase approach matches runc's setupRlimits.
     */
    private static void applyNofile(Syscalls sc, int pid, Spec.POSIXRlimit r) {
        int resource = Constants.RLIMIT_NOFILE;
        int rc = sc.prlimit64(pid, resource, r.soft, r.hard);
        if (rc == 0) {
            Logger.debug("rlimit " + r.type + " soft=" + r.soft + " hard=" + r.hard);
            return;
        }
        // First attempt failed. Try the two-phase approach: read nr_open,
        // set hard to nr_open, then set to the desired value.
        long nrOpen = readNrOpen();
        if (nrOpen <= 0 || r.hard <= nrOpen) {
            Logger.warn("prlimit64 " + r.type + " failed: " + sc.strerror(sc.errno()));
            return;
        }
        // Phase 1: raise hard to nr_open
        rc = sc.prlimit64(pid, resource, nrOpen, nrOpen);
        if (rc != 0) {
            Logger.warn("prlimit64 " + r.type + " (phase 1) failed: " + sc.strerror(sc.errno()));
            return;
        }
        // Phase 2: now raise above nr_open
        rc = sc.prlimit64(pid, resource, r.soft, r.hard);
        if (rc != 0) {
            // Fall back to nr_open as the maximum
            Logger.warn("prlimit64 " + r.type + " above nr_open failed, using nr_open="
                    + nrOpen);
            sc.prlimit64(pid, resource, Math.min(r.soft, nrOpen), nrOpen);
        } else {
            Logger.debug("rlimit " + r.type + " soft=" + r.soft + " hard=" + r.hard
                    + " (two-phase)");
        }
    }

    private static long readNrOpen() {
        try {
            String s = Files.readString(Path.of("/proc/sys/fs/nr_open")).trim();
            return Long.parseLong(s);
        } catch (Exception e) {
            return -1;
        }
    }

    private static int resourceId(String type) {
        return switch (type) {
            case "RLIMIT_CPU" -> Constants.RLIMIT_CPU;
            case "RLIMIT_FSIZE" -> Constants.RLIMIT_FSIZE;
            case "RLIMIT_DATA" -> Constants.RLIMIT_DATA;
            case "RLIMIT_STACK" -> Constants.RLIMIT_STACK;
            case "RLIMIT_CORE" -> Constants.RLIMIT_CORE;
            case "RLIMIT_RSS" -> Constants.RLIMIT_RSS;
            case "RLIMIT_NPROC" -> Constants.RLIMIT_NPROC;
            case "RLIMIT_NOFILE" -> Constants.RLIMIT_NOFILE;
            case "RLIMIT_MEMLOCK" -> Constants.RLIMIT_MEMLOCK;
            case "RLIMIT_AS" -> Constants.RLIMIT_AS;
            case "RLIMIT_LOCKS" -> Constants.RLIMIT_LOCKS;
            case "RLIMIT_SIGPENDING" -> Constants.RLIMIT_SIGPENDING;
            case "RLIMIT_MSGQUEUE" -> Constants.RLIMIT_MSGQUEUE;
            case "RLIMIT_NICE" -> Constants.RLIMIT_NICE;
            case "RLIMIT_RTPRIO" -> Constants.RLIMIT_RTPRIO;
            case "RLIMIT_RTTIME" -> Constants.RLIMIT_RTTIME;
            default -> -1;
        };
    }
}
