package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.cgroup.Cgroup;
import com.ternbusty.takoyaki.config.KontainerConfig;
import com.ternbusty.takoyaki.logger.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Shared helper for pause / resume — writes cgroup.freeze (cgroup v2). */
final class Freeze {
    private Freeze() {}

    static int write(String rootPath, String containerId, String value, String op) {
        String cgroupPath;
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath;
        } catch (IOException e) {
            System.err.println(op + " failed: no cgroup recorded for " + containerId);
            return 1;
        }
        if (cgroupPath == null) {
            System.err.println(op + " failed: container has no cgroupsPath");
            return 1;
        }
        Path freeze = Cgroup.dir(cgroupPath).resolve("cgroup.freeze");
        try {
            Files.writeString(freeze, value);
            Logger.info(op + " ok for " + containerId);
            return 0;
        } catch (IOException e) {
            System.err.println(op + " failed: " + e.getMessage());
            return 1;
        }
    }
}
