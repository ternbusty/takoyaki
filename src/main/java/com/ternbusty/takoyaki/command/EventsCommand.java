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

    public static int run(String rootPath, String containerId, boolean once, String interval) {
        String cgroupPath;
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath;
        } catch (IOException e) {
            System.err.println("container " + containerId + " does not exist");
            return 1;
        }
        if (cgroupPath == null) {
            System.err.println("no cgroupsPath for container");
            return 1;
        }
        long intervalMs = parseInterval(interval);
        Path cg = Cgroup.dir(cgroupPath);

        // Start OOM watcher thread that monitors memory.events for oom_kill.
        Thread oomWatcher = startOomWatcher(cg, containerId);

        // State directory disappears when the container is deleted; use it
        // as the liveness signal so the loop exits instead of spinning on a
        // removed cgroup path.
        Path statePath = Path.of(rootPath, containerId);

        do {
            if (!Files.isDirectory(cg) || !Files.isDirectory(statePath)) break;
            Map<String, Object> snap = snapshot(cg, containerId);
            System.out.println(Json.encodeCompact(snap));
            System.out.flush();
            if (once) break;
            try { Thread.sleep(intervalMs); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        } while (true);

        if (oomWatcher != null) oomWatcher.interrupt();
        return 0;
    }

    /** Monitor memory.events for oom_kill events and emit {"type":"oom"} JSON. */
    private static Thread startOomWatcher(Path cg, String containerId) {
        Path memEvents = cg.resolve("memory.events");
        if (!Files.exists(memEvents)) return null;
        Thread t = new Thread(() -> {
            long lastOomKill = readOomKillCount(memEvents);
            try (java.nio.file.WatchService ws = cg.getFileSystem().newWatchService()) {
                cg.register(ws, java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY);
                while (!Thread.currentThread().isInterrupted()) {
                    java.nio.file.WatchKey key = ws.take();
                    for (java.nio.file.WatchEvent<?> event : key.pollEvents()) {
                        if ("memory.events".equals(event.context().toString())) {
                            long current = readOomKillCount(memEvents);
                            if (current > lastOomKill) {
                                Map<String, Object> oomEvent = new LinkedHashMap<>();
                                oomEvent.put("type", "oom");
                                oomEvent.put("id", containerId);
                                System.out.println(Json.encodeCompact(oomEvent));
                                lastOomKill = current;
                            }
                        }
                    }
                    key.reset();
                }
            } catch (InterruptedException ignored) {
                // shutting down
            } catch (IOException e) {
                // memory.events not watchable, give up silently
            }
        }, "oom-watcher");
        t.setDaemon(true);
        t.start();
        return t;
    }

    /** Read the oom_kill count from cgroup v2 memory.events. */
    private static long readOomKillCount(Path memEvents) {
        Map<String, Long> kv = readKvFile(memEvents);
        if (kv == null) return 0;
        Long v = kv.get("oom_kill");
        return v != null ? v : 0;
    }

    /** Parse Go-style duration string (5s, 100ms, 1m, etc.) to milliseconds. */
    static long parseInterval(String s) {
        if (s == null || s.isEmpty()) return 5000;
        if (s.endsWith("ms")) {
            return Long.parseLong(s.substring(0, s.length() - 2));
        } else if (s.endsWith("s")) {
            return (long)(Double.parseDouble(s.substring(0, s.length() - 1)) * 1000);
        } else if (s.endsWith("m")) {
            return (long)(Double.parseDouble(s.substring(0, s.length() - 1)) * 60000);
        } else {
            try { return Long.parseLong(s) * 1000; } catch (NumberFormatException e) {
                return 5000;
            }
        }
    }

    private static Map<String, Object> snapshot(Path cg, String id) {
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("type", "stats");
        ev.put("id", id);
        Map<String, Object> data = new LinkedHashMap<>();
        Map<String, Object> memory = new LinkedHashMap<>();
        memory.put("usage", readKvFile(cg.resolve("memory.current"), true));
        memory.put("limit", readLong(cg.resolve("memory.max")));
        memory.put("cache", readLong(cg.resolve("memory.stat"), "file"));
        Map<String, Long> raw = readKvFile(cg.resolve("memory.stat"));
        if (raw != null) memory.put("raw", raw);
        data.put("memory", memory);
        Map<String, Object> cpu = new LinkedHashMap<>();
        Map<String, Object> cpuUsage = new LinkedHashMap<>();
        Map<String, Long> cpuStat = readKvFile(cg.resolve("cpu.stat"));
        if (cpuStat != null) {
            Long total = cpuStat.get("usage_usec");
            cpuUsage.put("total", total != null ? total * 1000 : 0L);
            Long user = cpuStat.get("user_usec");
            cpuUsage.put("user", user != null ? user * 1000 : 0L);
            Long system = cpuStat.get("system_usec");
            cpuUsage.put("kernel", system != null ? system * 1000 : 0L);
        }
        cpu.put("usage", cpuUsage);
        // PSI data
        Map<String, Object> psi = readPsi(cg.resolve("cpu.pressure"));
        if (psi != null) cpu.put("psi", psi);
        data.put("cpu", cpu);
        Map<String, Object> pids = new LinkedHashMap<>();
        pids.put("current", readLong(cg.resolve("pids.current")));
        pids.put("limit", readLong(cg.resolve("pids.max")));
        data.put("pids", pids);
        // hugetlb stats: scan for hugetlb.<pagesize>.current files
        Map<String, Object> hugetlb = readHugetlb(cg);
        if (hugetlb != null && !hugetlb.isEmpty()) {
            data.put("hugetlb", hugetlb);
        }
        ev.put("data", data);
        return ev;
    }

    /** Collect hugetlb stats from hugetlb.<pagesize>.{current,max,events} files. */
    private static Map<String, Object> readHugetlb(Path cg) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            for (Path p : Files.newDirectoryStream(cg, "hugetlb.*.current")) {
                // filename: hugetlb.<pagesize>.current
                String name = p.getFileName().toString();
                int dot1 = name.indexOf('.');
                int dot2 = name.lastIndexOf('.');
                if (dot1 < 0 || dot2 <= dot1) continue;
                String pageSize = name.substring(dot1 + 1, dot2);
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("usage", readLong(p));
                entry.put("max", readLong(cg.resolve("hugetlb." + pageSize + ".max")));
                entry.put("failcnt", readLong(cg.resolve("hugetlb." + pageSize + ".events"), "max"));
                result.put(pageSize, entry);
            }
        } catch (IOException ignored) {}
        return result;
    }

    /** Read a single-value cgroup file as a stats map or as a raw long. */
    private static Map<String, Long> readKvFile(Path p, boolean singleValue) {
        if (singleValue) {
            Long v = readLong(p);
            if (v == null) return null;
            Map<String, Long> m = new LinkedHashMap<>();
            m.put("usage", v);
            return m;
        }
        return readKvFile(p);
    }

    /** Read a specific key from a key-value cgroup file. */
    private static Long readLong(Path p, String key) {
        Map<String, Long> kv = readKvFile(p);
        return kv != null ? kv.get(key) : null;
    }

    /** Parse PSI pressure file into {some: {avg10,avg60,avg300,total}, full: {...}}. */
    private static Map<String, Object> readPsi(Path p) {
        if (!Files.exists(p)) return null;
        try {
            Map<String, Object> psi = new LinkedHashMap<>();
            for (String line : Files.readAllLines(p)) {
                // Format: some avg10=0.00 avg60=0.00 avg300=0.00 total=0
                String[] parts = line.split("\\s+");
                if (parts.length < 2) continue;
                String type = parts[0]; // "some" or "full"
                Map<String, Object> vals = new LinkedHashMap<>();
                for (int i = 1; i < parts.length; i++) {
                    String[] kv = parts[i].split("=");
                    if (kv.length == 2) {
                        try {
                            if (kv[1].contains(".")) {
                                vals.put(kv[0], Double.parseDouble(kv[1]));
                            } else {
                                vals.put(kv[0], Long.parseLong(kv[1]));
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                }
                psi.put(type, vals);
            }
            return psi.isEmpty() ? null : psi;
        } catch (IOException e) {
            return null;
        }
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
