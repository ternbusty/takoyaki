package com.ternbusty.takoyaki.cgroup;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public final class Cgroup {
    private static final String CGROUP_ROOT = "/sys/fs/cgroup";

    private Cgroup() {}

    public static void setup(int pid, String cgroupPath, Spec.Linux linux) {
        if (cgroupPath == null) return;
        String norm = cgroupPath.startsWith("/") ? cgroupPath.substring(1) : cgroupPath;
        Path full = Path.of(CGROUP_ROOT, norm);
        try {
            Files.createDirectories(full);
        } catch (IOException e) {
            Logger.warn("create cgroup dir failed: " + e.getMessage());
            return;
        }

        // Ensure controllers are enabled in the parent's subtree_control so this cgroup
        // can use them. Walk from root downward.
        enableControllers(full, linux != null ? linux.resources : null);

        applyLimits(full, linux != null ? linux.resources : null);

        try {
            Files.writeString(full.resolve("cgroup.procs"), Integer.toString(pid));
            Logger.debug("added pid " + pid + " to cgroup " + full);
        } catch (IOException e) {
            Logger.warn("add pid to cgroup failed: " + e.getMessage());
        }

        // eBPF device cgroup for resources.devices (cgroup v2 only path).
        if (linux != null && linux.resources != null && linux.resources.devices != null
                && !linux.resources.devices.isEmpty()) {
            DeviceCgroup.apply(cgroupPath, linux.resources.devices);
        }
    }

    private static void enableControllers(Path full, Spec.LinuxResources r) {
        java.util.List<String> needed = new java.util.ArrayList<>();
        if (r != null) {
            if (r.memory != null) needed.add("memory");
            if (r.cpu != null) {
                needed.add("cpu");
                if (r.cpu.cpus != null || r.cpu.mems != null) needed.add("cpuset");
            }
            if (r.pids != null) needed.add("pids");
        }
        if (needed.isEmpty()) return;
        // Walk up from full to CGROUP_ROOT to enable controllers in subtree_control
        Path root = Path.of(CGROUP_ROOT);
        java.util.List<Path> chain = new java.util.ArrayList<>();
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

    /** Re-apply resource limits to an existing cgroup (e.g. via `update`). */
    public static void applyLimitsOnly(String cgroupPath, Spec.LinuxResources r) {
        String norm = cgroupPath.startsWith("/") ? cgroupPath.substring(1) : cgroupPath;
        applyLimits(Path.of(CGROUP_ROOT, norm), r);
    }

    private static void applyLimits(Path full, Spec.LinuxResources r) {
        if (r == null) return;
        if (r.memory != null) {
            if (r.memory.limit != null) writeIfPossible(full.resolve("memory.max"),
                    r.memory.limit == -1L ? "max" : r.memory.limit.toString());
            if (r.memory.swap != null && r.memory.limit != null) {
                long swap = (r.memory.swap == -1L || r.memory.limit == -1L)
                        ? -1L
                        : r.memory.swap - r.memory.limit;
                writeIfPossible(full.resolve("memory.swap.max"), swap == -1L ? "max" : Long.toString(swap));
            }
            if (r.memory.reservation != null) writeIfPossible(full.resolve("memory.low"),
                    r.memory.reservation == -1L ? "max" : r.memory.reservation.toString());
        }
        if (r.cpu != null) {
            if (r.cpu.cpus != null && !r.cpu.cpus.isEmpty()) {
                writeIfPossible(full.resolve("cpuset.cpus"), r.cpu.cpus);
            }
            if (r.cpu.mems != null && !r.cpu.mems.isEmpty()) {
                writeIfPossible(full.resolve("cpuset.mems"), r.cpu.mems);
            }
            if (r.cpu.shares != null && r.cpu.shares > 0) {
                long w = 1 + ((r.cpu.shares - 2L) * 9999L / 262142L);
                if (w > 10000L) w = 10000L;
                writeIfPossible(full.resolve("cpu.weight"), Long.toString(w));
            }
            if (r.cpu.quota != null || r.cpu.period != null) {
                String q = r.cpu.quota == null || r.cpu.quota <= 0 ? "max" : Long.toString(r.cpu.quota);
                String p = r.cpu.period == null ? "100000" : Long.toString(r.cpu.period);
                writeIfPossible(full.resolve("cpu.max"), q + " " + p);
            }
            // Realtime scheduling limits are a cgroup v1 concept — v2 removed
            // cpu.rt_period_us / cpu.rt_runtime_us entirely. Silently ignoring
            // the field would hide a genuine spec violation from the user;
            // surface it so they at least see it in the logs.
            if (r.cpu.realtimePeriod != null || r.cpu.realtimeRuntime != null) {
                Logger.warn("cpu.realtimePeriod / realtimeRuntime are not supported"
                        + " on cgroup v2; ignoring");
            }
        }
        if (r.pids != null && r.pids.limit > 0) {
            writeIfPossible(full.resolve("pids.max"), Long.toString(r.pids.limit));
        }
        // Unified pass-through: any arbitrary control-file the spec author
        // named gets written verbatim. Applied last so it can override the
        // strongly typed fields above if the same file was set both ways.
        if (r.unified != null && !r.unified.isEmpty()) {
            for (Map.Entry<String, String> e : r.unified.entrySet()) {
                writeIfPossible(full.resolve(e.getKey()), e.getValue());
            }
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
        String norm = cgroupPath.startsWith("/") ? cgroupPath.substring(1) : cgroupPath;
        Path full = Path.of(CGROUP_ROOT, norm);
        if (!Files.exists(full)) return;

        // cgroup v2: writing "1" to cgroup.kill sends SIGKILL to every process
        // in this cgroup (Linux 5.14+). Best-effort — older kernels don't have
        // the file and the parent's SIGKILL on state.pid handles that path.
        try {
            Files.writeString(full.resolve("cgroup.kill"), "1");
        } catch (IOException ignored) {}

        // rmdir(2) on a cgroup v2 directory returns EBUSY ("Device or resource
        // busy") even briefly after the cgroup empties — the kernel runs an
        // async tear-down (cgroup_destroy_locked schedules work). Polling
        // cgroup.procs isn't enough to gate rmdir; we need to retry rmdir
        // itself. runc does the same in libcontainer/cgroups/fs2.
        IOException last = null;
        long deadlineNs = System.nanoTime() + 5_000_000_000L;
        while (System.nanoTime() < deadlineNs) {
            try {
                Files.delete(full);
                Logger.debug("cgroup dir removed: " + full);
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
        Logger.warn("cgroup cleanup failed (" + full + "): "
                + (last != null ? last.getMessage() : "deadline elapsed"));
    }
}
