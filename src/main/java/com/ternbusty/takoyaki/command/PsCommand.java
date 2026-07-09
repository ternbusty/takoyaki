package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.cgroup.Cgroup;
import com.ternbusty.takoyaki.config.KontainerConfig;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.util.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class PsCommand {
    private PsCommand() {}

    public static int run(String rootPath, String containerId, String format) {
        State state;
        try {
            state = State.load(rootPath, containerId).refreshStatus();
        } catch (Exception e) {
            Logger.error("failed to load state: " + e.getMessage());
            return 1;
        }
        String cgroupPath = null;
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath;
        } catch (IOException ignored) {}

        List<Integer> pids = new ArrayList<>();
        if (cgroupPath != null) {
            Path procs = Cgroup.dir(cgroupPath).resolve("cgroup.procs");
            try {
                for (String line : Files.readAllLines(procs)) {
                    String t = line.trim();
                    if (!t.isEmpty()) pids.add(Integer.parseInt(t));
                }
            } catch (IOException e) {
                Logger.debug("read " + procs + " failed: " + e.getMessage());
            }
        }
        if (pids.isEmpty() && state.pid != null) pids.add(state.pid);

        if ("json".equals(format)) {
            System.out.println(Json.encode(pids));
            return 0;
        }
        System.out.printf("%-8s %s%n", "PID", "CMD");
        for (int pid : pids) {
            String cmd = "";
            try {
                cmd = Files.readString(Path.of("/proc", String.valueOf(pid), "cmdline"))
                        .replace('\0', ' ').trim();
            } catch (IOException ignored) {}
            System.out.printf("%-8d %s%n", pid, cmd);
        }
        return 0;
    }
}
