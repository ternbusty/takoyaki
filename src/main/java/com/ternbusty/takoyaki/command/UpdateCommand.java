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
                          String resourcesPath, Long memory,
                          Long cpuQuota, Long cpuPeriod, Long cpuShares,
                          Long pidsLimit) {
        String cgroupPath;
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath;
        } catch (Exception e) {
            Logger.error("no kontainer config: " + e.getMessage());
            return 1;
        }
        if (cgroupPath == null) {
            Logger.error("container has no cgroupsPath");
            return 1;
        }

        Spec.LinuxResources r = new Spec.LinuxResources();
        if (resourcesPath != null) {
            try {
                Spec.LinuxResources parsed = Json.readFile(Path.of(resourcesPath),
                        Spec.LinuxResources::fromJson);
                r = parsed;
            } catch (Exception e) {
                Logger.error("failed to read resources file: " + e.getMessage());
                return 1;
            }
        }
        if (memory != null) {
            if (r.memory == null) r.memory = new Spec.LinuxMemory();
            r.memory.limit = memory;
        }
        if (cpuQuota != null || cpuPeriod != null || cpuShares != null) {
            if (r.cpu == null) r.cpu = new Spec.LinuxCpu();
            if (cpuQuota != null) r.cpu.quota = cpuQuota;
            if (cpuPeriod != null) r.cpu.period = cpuPeriod;
            if (cpuShares != null) r.cpu.shares = cpuShares;
        }
        if (pidsLimit != null) {
            if (r.pids == null) r.pids = new Spec.LinuxPids();
            r.pids.limit = pidsLimit;
        }

        // Reuse the existing cgroup directory; just rewrite limits.
        Cgroup.applyLimitsOnly(cgroupPath, r);
        Logger.info("updated resources for " + containerId);
        return 0;
    }
}
