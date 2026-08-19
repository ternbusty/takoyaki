package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.cgroup.Cgroup;
import com.ternbusty.takoyaki.config.KontainerConfig;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.util.Json;

import java.nio.file.Path;

public final class UpdateCommand {
    private UpdateCommand() {}

    public static int run(String rootPath, String containerId,
                          String resourcesPath, Long memory, Long memoryReservation,
                          Long memorySwap, Long cpuQuota, Long cpuPeriod,
                          Long cpuShares, Long pidsLimit, String cpusetCpus,
                          Long cpuBurst, Long cpuIdle) {
        String cgroupPath;
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath;
        } catch (Exception e) {
            System.err.println("container " + containerId + " does not exist");
            return 1;
        }
        if (cgroupPath == null) {
            System.err.println("container has no cgroupsPath");
            return 1;
        }

        Spec.LinuxResources r = new Spec.LinuxResources();
        if (resourcesPath != null) {
            try {
                Spec.LinuxResources parsed = Json.readFile(Path.of(resourcesPath),
                        Spec.LinuxResources::fromJson);
                r = parsed;
            } catch (Exception e) {
                System.err.println("failed to read resources file: " + e.getMessage());
                return 1;
            }
        }
        if (memory != null) {
            if (r.memory == null) r.memory = new Spec.LinuxMemory();
            r.memory.limit = memory;
            // runc compat: when memory limit is removed (-1), swap is also
            // removed unless an explicit --memory-swap value was given.
            if (memory == -1L && memorySwap == null && r.memory.swap == null) {
                r.memory.swap = -1L;
            }
        }
        if (memoryReservation != null) {
            if (r.memory == null) r.memory = new Spec.LinuxMemory();
            r.memory.reservation = memoryReservation;
        }
        if (memorySwap != null) {
            if (r.memory == null) r.memory = new Spec.LinuxMemory();
            r.memory.swap = memorySwap;
            // For cgroup v2, swap is relative to memory. Need memory limit to
            // compute the delta. If memory was not given on this invocation,
            // read the current value from the cgroup.
            if (r.memory.limit == null) {
                try {
                    String cur = java.nio.file.Files.readString(
                            Cgroup.dir(cgroupPath).resolve("memory.max")).trim();
                    if (!"max".equals(cur)) {
                        r.memory.limit = Long.parseLong(cur);
                    }
                } catch (Exception ignored) {}
            }
        }
        if (cpuQuota != null || cpuPeriod != null || cpuShares != null
                || cpuBurst != null || cpuIdle != null) {
            if (r.cpu == null) r.cpu = new Spec.LinuxCpu();
            if (cpuQuota != null) r.cpu.quota = cpuQuota;
            if (cpuPeriod != null) r.cpu.period = cpuPeriod;
            if (cpuShares != null) r.cpu.shares = cpuShares;
            if (cpuBurst != null) r.cpu.burst = cpuBurst;
            if (cpuIdle != null) {
                if (cpuIdle != 0 && cpuIdle != 1) {
                    System.err.println("invalid value for cpu.idle: must be 0 or 1, got " + cpuIdle);
                    return 1;
                }
                r.cpu.idle = cpuIdle;
            }
        }
        if (cpusetCpus != null) {
            if (r.cpu == null) r.cpu = new Spec.LinuxCpu();
            r.cpu.cpus = cpusetCpus;
        }
        if (pidsLimit != null) {
            if (r.pids == null) r.pids = new Spec.LinuxPids();
            r.pids.limit = pidsLimit;
        }

        // Validate cpu.idle regardless of source (CLI or JSON).
        if (r.cpu != null && r.cpu.idle != null && r.cpu.idle != 0 && r.cpu.idle != 1) {
            System.err.println("invalid value for cpu.idle: must be 0 or 1, got " + r.cpu.idle);
            return 1;
        }

        // runc compat: checkBeforeUpdate prevents setting memory limits
        // below current usage, avoiding instant OOM kills.
        if (r.memory != null && Boolean.TRUE.equals(r.memory.checkBeforeUpdate)) {
            java.nio.file.Path cgDir = Cgroup.dir(cgroupPath);
            if (r.memory.limit != null && r.memory.limit > 0) {
                long usage = readCgroupLong(cgDir.resolve("memory.current"));
                if (usage > 0 && r.memory.limit < usage) {
                    System.err.println("rejecting memory limit " + r.memory.limit
                            + " (current usage is " + usage + ")");
                    return 1;
                }
            }
            if (r.memory.swap != null && r.memory.swap > 0 && r.memory.limit != null) {
                long memUsage = readCgroupLong(cgDir.resolve("memory.current"));
                long swapUsage = readCgroupLong(cgDir.resolve("memory.swap.current"));
                long totalUsage = memUsage + swapUsage;
                if (totalUsage > 0 && r.memory.swap < totalUsage) {
                    System.err.println("rejecting memory+swap limit " + r.memory.swap
                            + " (current usage is " + totalUsage + ")");
                    return 1;
                }
            }
        }

        Cgroup.applyLimitsOnly(cgroupPath, r);
        return 0;
    }

    private static long readCgroupLong(java.nio.file.Path p) {
        try {
            String v = java.nio.file.Files.readString(p).trim();
            if ("max".equals(v)) return Long.MAX_VALUE;
            return Long.parseLong(v);
        } catch (Exception e) {
            return -1;
        }
    }
}
