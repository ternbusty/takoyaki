package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.cgroup.Cgroup;
import com.ternbusty.takoyaki.config.KontainerConfig;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.util.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Stream resource-usage statistics from the container's cgroup. Without --stats we
 * fall through to a polling loop similar to `runc events`. The format is JSON Lines.
 */
public final class EventsCommand {
    private EventsCommand() {}

    public static int run(String rootPath, String containerId, boolean once, int intervalSec) {
        String cgroupPath;
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath;
        } catch (IOException e) {
            Logger.error("no cgroup recorded: " + e.getMessage());
            return 1;
        }
        if (cgroupPath == null) {
            Logger.error("no cgroupsPath for container");
            return 1;
        }
        Path cg = Cgroup.dir(cgroupPath);
        do {
            Map<String, Object> snap = snapshot(cg, containerId);
            System.out.println(Json.encode(snap));
            if (once) break;
            try { Thread.sleep(intervalSec * 1000L); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        } while (true);
        return 0;
    }

    private static Map<String, Object> snapshot(Path cg, String id) {
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("id", id);
        ev.put("type", "stats");
        Map<String, Object> data = new HashMap<>();
        Map<String, Object> memory = new HashMap<>();
        memory.put("usage", readLong(cg.resolve("memory.current")));
        memory.put("limit", readString(cg.resolve("memory.max")));
        memory.put("events", readKvFile(cg.resolve("memory.events")));
        data.put("memory", memory);
        Map<String, Object> cpu = new HashMap<>();
        cpu.put("stat", readKvFile(cg.resolve("cpu.stat")));
        data.put("cpu", cpu);
        Map<String, Object> pids = new HashMap<>();
        pids.put("current", readLong(cg.resolve("pids.current")));
        pids.put("limit", readString(cg.resolve("pids.max")));
        data.put("pids", pids);
        ev.put("data", data);
        return ev;
    }

    private static Long readLong(Path p) {
        String s = readString(p);
        if (s == null) return null;
        try { return Long.parseLong(s.trim()); } catch (NumberFormatException e) { return null; }
    }

    private static String readString(Path p) {
        try { return Files.readString(p).trim(); }
        catch (IOException e) { return null; }
    }

    private static Map<String, Long> readKvFile(Path p) {
        Map<String, Long> kv = new LinkedHashMap<>();
        try {
            for (String line : Files.readAllLines(p)) {
                String[] parts = line.split("\\s+");
                if (parts.length == 2) {
                    try { kv.put(parts[0], Long.parseLong(parts[1])); } catch (NumberFormatException ignored) {}
                }
            }
        } catch (IOException ignored) {}
        return kv;
    }
}
