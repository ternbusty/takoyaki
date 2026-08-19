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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class PsCommand {
    private PsCommand() {}

    public static int run(String rootPath, String containerId, String format,
                          List<String> psArgs) {
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
        // Run the host "ps" command and filter to only container pids.
        // runc default is "ps -ef" when no extra args are given.
        return runHostPs(pids, psArgs);
    }

    /** Execute host ps and filter output to only show container PIDs. */
    private static int runHostPs(List<Integer> pids, List<String> psArgs) {
        Set<Integer> pidSet = new HashSet<>(pids);
        List<String> cmd = new ArrayList<>();
        cmd.add("ps");
        if (psArgs == null || psArgs.isEmpty()) {
            cmd.add("-ef");
        } else {
            cmd.addAll(psArgs);
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String output = new String(p.getInputStream().readAllBytes());
            int rc = p.waitFor();
            if (rc != 0) {
                System.err.print(output);
                return rc;
            }
            String[] lines = output.split("\n");
            if (lines.length > 0) {
                // Print header
                System.out.println(lines[0]);
            }
            for (int i = 1; i < lines.length; i++) {
                // Extract PID from the line. For "ps -ef" format, PID is the
                // second whitespace-delimited field. For "ps -e -x" format,
                // PID is the first field (possibly with leading spaces).
                String line = lines[i];
                int pidFromLine = extractPid(line);
                if (pidFromLine >= 0 && pidSet.contains(pidFromLine)) {
                    System.out.println(line);
                }
            }
            return 0;
        } catch (Exception e) {
            System.err.println("failed to run ps: " + e.getMessage());
            return 1;
        }
    }

    /** Extract PID from a ps output line. Tries multiple common formats. */
    private static int extractPid(String line) {
        String[] parts = line.trim().split("\\s+");
        if (parts.length < 2) return -1;
        // Try first field (BSD-style: PID TTY STAT ...)
        try {
            return Integer.parseInt(parts[0]);
        } catch (NumberFormatException ignored) {}
        // Try second field (SysV-style: UID PID PPID ...)
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException ignored) {}
        return -1;
    }
}
