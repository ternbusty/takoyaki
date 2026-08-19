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
            if (cpuIdle != null) r.cpu.idle = cpuIdle;
        }
        if (cpusetCpus != null) {
            if (r.cpu == null) r.cpu = new Spec.LinuxCpu();
            r.cpu.cpus = cpusetCpus;
        }
        if (pidsLimit != null) {
            if (r.pids == null) r.pids = new Spec.LinuxPids();
            r.pids.limit = pidsLimit;
        }

        Cgroup.applyLimitsOnly(cgroupPath, r);
        return 0;
    }
}
