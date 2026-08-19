package com.ternbusty.takoyaki.cgroup;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Cgroup {
    private static final String CGROUP_ROOT = "/sys/fs/cgroup";

    /**
     * Controllers that can actually be enabled via cgroup.subtree_control.
     * Used to filter control-file prefixes: "memory.max" names the memory
     * controller, but "cgroup.freeze" (possible via resources.unified) does
     * not name a controller at all.
     */
    private static final Set<String> KNOWN_CONTROLLERS =
            Set.of("cpu", "cpuset", "memory", "pids", "io", "hugetlb");

    /**
     * Control files whose write failures should propagate as exceptions during
     * container setup (strict mode). These are the core resource files; an
     * invalid value (e.g. too-small period) should abort create rather than
     * silently succeed.
     */
    private static final Set<String> STRICT_FILES = Set.of(
            "cpu.max", "cpu.weight", "cpu.idle",
            "cpuset.cpus", "cpuset.mems",
            "memory.max", "memory.low", "memory.swap.max",
            "pids.max");

    private Cgroup() {}

    /**
     * Resolve an OCI cgroupsPath (with or without a leading '/') to its
     * directory under the cgroup v2 mount.
     */
    public static Path dir(String cgroupPath) {
        String norm = cgroupPath.startsWith("/") ? cgroupPath.substring(1) : cgroupPath;
        return Path.of(CGROUP_ROOT, norm);
    }

    public static void setup(int pid, String cgroupPath, Spec.Linux linux) {
        if (cgroupPath == null) return;
        Path full = dir(cgroupPath);
        try {
            Files.createDirectories(full);
        } catch (IOException e) {
            Logger.warn("create cgroup dir failed: " + e.getMessage());
            return;
        }

        // Reject if the cgroup already has processes (runc compat: error for
        // a non-empty cgroup to avoid resource conflicts).
        try {
            String procs = Files.readString(full.resolve("cgroup.procs")).trim();
            if (!procs.isEmpty()) {
                throw new RuntimeException(
                        "container's cgroup is not empty: " + full);
            }
        } catch (IOException ignored) {
            // cgroup.procs not readable yet (newly created directory)
        }

        // Reject if the cgroup is already frozen (runc compat).
        try {
            String freeze = Files.readString(full.resolve("cgroup.freeze")).trim();
            if ("1".equals(freeze)) {
                throw new RuntimeException(
                        "container's cgroup unexpectedly frozen");
            }
        } catch (IOException ignored) {
            // cgroup.freeze not available (newly created or no freezer)
        }

        // Ensure controllers are enabled in the parent's subtree_control so this cgroup
        // can use them. Walk from root downward.
        enableControllers(full, linux != null ? linux.resources : null);

        applyLimits(full, linux != null ? linux.resources : null, true);

        addPid(cgroupPath, pid);

        // eBPF device cgroup for resources.devices (cgroup v2 only path).
        if (linux != null && linux.resources != null && linux.resources.devices != null
                && !linux.resources.devices.isEmpty()) {
            DeviceCgroup.apply(cgroupPath, linux.resources.devices);
        }
    }

    /**
     * Move a pid into an already-configured cgroup. Writes cgroup.procs only;
     * directory creation, controller enablement, limits, and the device BPF
     * program are all left untouched (see setup for the full path).
     */
    public static void addPid(String cgroupPath, long pid) {
        if (cgroupPath == null) return;
        Path full = dir(cgroupPath);
        try {
            Files.writeString(full.resolve("cgroup.procs"), Long.toString(pid));
            Logger.debug("added pid " + pid + " to cgroup " + full);
        } catch (IOException e) {
            Logger.warn("add pid to cgroup failed: " + e.getMessage());
        }
    }

    private static void enableControllers(Path full, Spec.LinuxResources r) {
        // Derive the needed controller set from the control files applyLimits
        // is about to write: the prefix before the first '.' names the
        // controller ("memory.max" -> memory). This handles the strongly
        // typed fields and resources.unified keys uniformly.
        Set<String> needed = new LinkedHashSet<>();
        for (Map.Entry<String, String> e : plannedWrites(r)) {
            String file = e.getKey();
            int dot = file.indexOf('.');
            if (dot > 0) {
                String ctrl = file.substring(0, dot);
                if (KNOWN_CONTROLLERS.contains(ctrl)) needed.add(ctrl);
            }
        }
        if (needed.isEmpty()) return;
        // Walk up from full to CGROUP_ROOT to enable controllers in subtree_control
        Path root = Path.of(CGROUP_ROOT);
        List<Path> chain = new ArrayList<>();
        Path cur = full.getParent();
        while (cur != null && cur.startsWith(root)) {
            chain.add(0, cur);
            if (cur.equals(root)) break;
            cur = cur.getParent();
        }
        for (Path p : chain) {
            Path sc = p.resolve("cgroup.subtree_control");
            for (String ctrl : needed) {
                try {
                    Files.writeString(sc, "+" + ctrl);
                } catch (IOException ignored) {}
            }
        }
    }

    /** Re-apply resource limits to an existing cgroup (e.g. via `update`).
     *  Also enables any new controllers required by the update. */
    public static void applyLimitsOnly(String cgroupPath, Spec.LinuxResources r) {
        Path full = dir(cgroupPath);
        enableControllers(full, r);
        applyLimits(full, r);
    }

    private static void applyLimits(Path full, Spec.LinuxResources r) {
        applyLimits(full, r, false);
    }

    private static void applyLimits(Path full, Spec.LinuxResources r, boolean strict) {
        if (r == null) return;
        // Realtime scheduling limits are a cgroup v1 concept — v2 removed
        // cpu.rt_period_us / cpu.rt_runtime_us entirely. Silently ignoring
        // the field would hide a genuine spec violation from the user;
        // surface it so they at least see it in the logs.
        if (r.cpu != null && (r.cpu.realtimePeriod != null || r.cpu.realtimeRuntime != null)) {
            Logger.warn("cpu.realtimePeriod / realtimeRuntime are not supported"
                    + " on cgroup v2; ignoring");
        }
        for (Map.Entry<String, String> e : plannedWrites(r)) {
            if (strict && STRICT_FILES.contains(e.getKey())) {
                writeRequired(full.resolve(e.getKey()), e.getValue());
            } else {
                writeIfPossible(full.resolve(e.getKey()), e.getValue());
            }
        }
    }

    /**
     * The control-file writes derived from the spec resources, in application
     * order. Drives both applyLimits (the writes themselves) and
     * enableControllers (the controller set). resources.unified entries come
     * last so they can override the strongly typed fields if the same file
     * was set both ways.
     */
    private static List<Map.Entry<String, String>> plannedWrites(Spec.LinuxResources r) {
        List<Map.Entry<String, String>> writes = new ArrayList<>();
        if (r == null) return writes;
        if (r.memory != null) {
            if (r.memory.limit != null) writes.add(Map.entry("memory.max",
                    r.memory.limit == -1L ? "max" : r.memory.limit.toString()));
            if (r.memory.swap != null && r.memory.limit != null) {
                long swap = (r.memory.swap == -1L || r.memory.limit == -1L)
                        ? -1L
                        : r.memory.swap - r.memory.limit;
                writes.add(Map.entry("memory.swap.max", swap == -1L ? "max" : Long.toString(swap)));
            }
            if (r.memory.reservation != null) writes.add(Map.entry("memory.low",
                    r.memory.reservation == -1L ? "max" : r.memory.reservation.toString()));
        }
        if (r.cpu != null) {
            if (r.cpu.cpus != null && !r.cpu.cpus.isEmpty()) {
                writes.add(Map.entry("cpuset.cpus", r.cpu.cpus));
            }
            if (r.cpu.mems != null && !r.cpu.mems.isEmpty()) {
                writes.add(Map.entry("cpuset.mems", r.cpu.mems));
            }
            if (r.cpu.shares != null && r.cpu.shares > 0) {
                long w = convertSharesToWeight(r.cpu.shares);
                writes.add(Map.entry("cpu.weight", Long.toString(w)));
            }
            if (r.cpu.quota != null || r.cpu.period != null) {
                String q = r.cpu.quota == null || r.cpu.quota <= 0 ? "max" : Long.toString(r.cpu.quota);
                String p = r.cpu.period == null ? "100000" : Long.toString(r.cpu.period);
                writes.add(Map.entry("cpu.max", q + " " + p));
            }
            // cpu.max.burst is a separate control file since Linux 5.14.
            // Writing before the kernel supports it just fails with ENOENT
            // and writeIfPossible logs at warn — acceptable.
            if (r.cpu.burst != null && r.cpu.burst >= 0) {
                writes.add(Map.entry("cpu.max.burst", Long.toString(r.cpu.burst)));
            }
            // cpu.idle non-zero moves the cgroup to SCHED_IDLE. Linux 5.15+.
            if (r.cpu.idle != null) {
                writes.add(Map.entry("cpu.idle", Long.toString(r.cpu.idle)));
            }
        }
        if (r.pids != null) {
            if (r.pids.limit == -1L) {
                // runc: -1 means unlimited ("max")
                writes.add(Map.entry("pids.max", "max"));
            } else if (r.pids.limit == 0L) {
                // runc: 0 is silently remapped to 1 (TasksMax=0 is invalid)
                writes.add(Map.entry("pids.max", "1"));
            } else if (r.pids.limit > 0) {
                writes.add(Map.entry("pids.max", Long.toString(r.pids.limit)));
            }
        }
        // hugepageLimits: each entry lands in its own hugetlb.<size>.max file.
        // Runc uses the same pageSize→filename mapping.
        if (r.hugepageLimits != null) {
            for (Spec.LinuxHugepageLimit h : r.hugepageLimits) {
                if (h.pageSize == null || h.limit == null) continue;
                writes.add(Map.entry("hugetlb." + h.pageSize + ".max", h.limit.toString()));
            }
        }
        if (r.blockIO != null) {
            appendBlockIO(writes, r.blockIO);
        }
        // Unified pass-through: any arbitrary control-file the spec author
        // named gets written verbatim.
        if (r.unified != null) {
            for (Map.Entry<String, String> e : r.unified.entrySet()) {
                writes.add(Map.entry(e.getKey(), e.getValue()));
            }
        }
        return writes;
    }

    /**
     * Emit cgroup v2 io.* files from an OCI blockIO block.
     *
     * OCI's blockIO is a v1-era shape (weight + throttleRead/Write*), so we
     * translate each into its v2 equivalent:
     *   weight                 -> io.weight (unqualified, default for the cgroup)
     *   throttleRead/WriteBps  -> io.max "major:minor rbps=… wbps=…"
     *   throttleRead/WriteIOPS -> io.max "major:minor riops=… wiops=…"
     * Multiple entries for the same major:minor get merged so the kernel
     * doesn't clobber a previous write.
     */
    private static void appendBlockIO(List<Map.Entry<String, String>> writes, Spec.LinuxBlockIO io) {
        if (io.weight != null && io.weight > 0) {
            writes.add(Map.entry("io.weight", "default " + io.weight));
        }
        java.util.Map<String, StringBuilder> perDevice = new java.util.LinkedHashMap<>();
        appendThrottle(perDevice, io.throttleReadBpsDevice, "rbps");
        appendThrottle(perDevice, io.throttleWriteBpsDevice, "wbps");
        appendThrottle(perDevice, io.throttleReadIOPSDevice, "riops");
        appendThrottle(perDevice, io.throttleWriteIOPSDevice, "wiops");
        for (var e : perDevice.entrySet()) {
            writes.add(Map.entry("io.max", e.getKey() + " " + e.getValue().toString().trim()));
        }
    }

    private static void appendThrottle(java.util.Map<String, StringBuilder> perDevice,
                                       java.util.List<Spec.LinuxThrottleDevice> devs,
                                       String key) {
        if (devs == null) return;
        for (Spec.LinuxThrottleDevice d : devs) {
            if (d.major == null || d.minor == null || d.rate == null) continue;
            String dev = d.major + ":" + d.minor;
            perDevice.computeIfAbsent(dev, k -> new StringBuilder())
                    .append(key).append('=').append(d.rate).append(' ');
        }
    }

    private static void writeRequired(Path p, String v) {
        try {
            Files.writeString(p, v);
            Logger.debug("set " + p.getFileName() + "=" + v);
        } catch (IOException e) {
            throw new RuntimeException(
                    "unable to set " + p.getFileName() + " to \"" + v + "\": " + e.getMessage());
        }
    }

    private static void writeIfPossible(Path p, String v) {
        try {
            Files.writeString(p, v);
            Logger.debug("set " + p.getFileName() + "=" + v);
        } catch (IOException e) {
            Logger.warn("write " + p + " (" + v + "): " + e.getMessage());
        }
    }

    public static void cleanup(String cgroupPath) {
        if (cgroupPath == null) return;
        Path full = dir(cgroupPath);
        if (!Files.exists(full)) return;

        // Kill all processes in this cgroup tree (including subcgroups).
        killCgroupTree(full);

        // Wait for all processes to actually exit from the cgroup. The kernel
        // needs time to reap killed processes, and they must disappear from
        // cgroup.procs before rmdir can succeed.
        waitForEmpty(full);

        // Remove subcgroup directories bottom-up, then the main directory.
        // Subcgroups must be removed before the parent (kernel requirement).
        try {
            removeSubcgroups(full);
        } catch (IOException e) {
            Logger.debug("subcgroup cleanup: " + e.getMessage());
        }

        // rmdir(2) on a cgroup v2 directory returns EBUSY ("Device or resource
        // busy") even briefly after the cgroup empties — the kernel runs an
        // async tear-down (cgroup_destroy_locked schedules work). Polling
        // cgroup.procs isn't enough to gate rmdir; we need to retry rmdir
        // itself. runc does the same in libcontainer/cgroups/fs2.
        retryRmdir(full);
    }

    /**
     * Send SIGKILL to every process in the cgroup tree rooted at {@code dir}.
     * Uses cgroup.kill (Linux 5.14+) where available, falling back to reading
     * cgroup.procs.
     */
    private static void killCgroupTree(Path dir) {
        // Try cgroup.kill first (applies to subtree)
        try {
            Files.writeString(dir.resolve("cgroup.kill"), "1");
            return;
        } catch (IOException ignored) {}

        // Fallback: iterate subcgroups and kill manually
        try (java.util.stream.Stream<Path> children = Files.list(dir)) {
            children.filter(Files::isDirectory).forEach(Cgroup::killCgroupTree);
        } catch (IOException ignored) {}
        try {
            String procs = Files.readString(dir.resolve("cgroup.procs")).trim();
            if (!procs.isEmpty()) {
                for (String line : procs.split("\n")) {
                    try {
                        int pid = Integer.parseInt(line.trim());
                        com.ternbusty.takoyaki.syscall.Libc.kill(pid,
                                com.ternbusty.takoyaki.syscall.Constants.SIGKILL);
                    } catch (NumberFormatException ignored) {}
                }
            }
        } catch (IOException ignored) {}
    }

    /**
     * Recursively remove subcgroup directories (depth-first). Each subcgroup is
     * removed with retryRmdir to handle the async kernel teardown. Leaves the
     * top-level {@code dir} in place for the caller to remove.
     */
    private static void removeSubcgroups(Path dir) throws IOException {
        try (java.util.stream.Stream<Path> children = Files.list(dir)) {
            for (Path child : children.toList()) {
                if (Files.isDirectory(child) && !Files.isSymbolicLink(child)) {
                    removeSubcgroups(child);
                    retryRmdir(child);
                }
            }
        }
    }

    /**
     * Wait for cgroup.procs (and children's) to become empty after a kill.
     * Gives the kernel up to 5 seconds for processes to be reaped.
     */
    private static void waitForEmpty(Path dir) {
        long deadlineNs = System.nanoTime() + 5_000_000_000L;
        while (System.nanoTime() < deadlineNs) {
            if (isTreeEmpty(dir)) return;
            try { Thread.sleep(10); }
            catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        Logger.debug("cgroup tree not fully empty after 5s: " + dir);
    }

    /** Check if cgroup.procs is empty in this dir and all subdirectories. */
    private static boolean isTreeEmpty(Path dir) {
        try {
            String procs = Files.readString(dir.resolve("cgroup.procs")).trim();
            if (!procs.isEmpty()) return false;
        } catch (IOException e) {
            return true; // can't read → treat as empty
        }
        try (java.util.stream.Stream<Path> children = Files.list(dir)) {
            for (Path child : children.toList()) {
                if (Files.isDirectory(child) && !Files.isSymbolicLink(child)) {
                    if (!isTreeEmpty(child)) return false;
                }
            }
        } catch (IOException e) {
            // can't list children → ok
        }
        return true;
    }

    /** Retry rmdir with back-off for up to 5 seconds. */
    private static void retryRmdir(Path dir) {
        IOException last = null;
        long deadlineNs = System.nanoTime() + 5_000_000_000L;
        while (System.nanoTime() < deadlineNs) {
            try {
                Files.delete(dir);
                Logger.debug("cgroup dir removed: " + dir);
                return;
            } catch (java.nio.file.NoSuchFileException e) {
                return;
            } catch (IOException e) {
                last = e;
                try { Thread.sleep(20); }
                catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        Logger.warn("cgroup cleanup failed (" + dir + "): "
                + (last != null ? last.getMessage() : "deadline elapsed"));
    }

    /**
     * Convert cgroup v1 CPU shares to cgroup v2 weight using the same
     * logarithmic formula as runc's {@code ConvertCPUSharesToCgroupV2Value}.
     * cgroup v1 shares (2..262144) are on an exponential scale, while v2
     * weights (1..10000) are linear.  A naive linear interpolation would
     * compress the low end; this log-based conversion preserves proportional
     * relationships.
     */
    static long convertSharesToWeight(long shares) {
        if (shares == 0) return 0;
        if (shares <= 2) return 1;
        if (shares >= 262144) return 10000;
        double l = Math.log(shares) / Math.log(2);
        double exponent = (l * l + 125.0 * l) / 612.0 - 7.0 / 34.0;
        return (long) (Math.pow(10, exponent) + 0.99);
    }
}
