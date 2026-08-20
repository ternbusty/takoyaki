package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.util.Json;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class ListCommand {
    private ListCommand() {}

    public static int run(String rootPath, String format, boolean quiet) {
        Path rootDir = Path.of(rootPath);
        if (!Files.isDirectory(rootDir)) {
            // runc behaviour: `list` with the default root succeeds even when
            // the directory does not exist yet (no containers have been
            // created). But if the user passed an explicit --root that does not
            // exist, return an error.
            if (isDefaultRoot(rootPath)) {
                if ("json".equals(format)) System.out.println("[]");
                return 0;
            }
            System.err.println("\"" + rootPath + "\" does not exist");
            return 1;
        }
        List<State> states = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(rootDir)) {
            for (Path child : ds) {
                if (!Files.isDirectory(child)) continue;
                try {
                    State s = State.load(rootPath, child.getFileName().toString())
                            .refreshStatus();
                    states.add(s);
                } catch (Exception ignored) {}
            }
        } catch (IOException e) {
            Logger.error("list failed: " + e.getMessage());
            return 1;
        }

        // runc sorts containers by ID (alphabetical order).
        states.sort(java.util.Comparator.comparing(s -> s.id));

        if (quiet) {
            for (State s : states) System.out.println(s.id);
            return 0;
        }
        if ("json".equals(format)) {
            // runc list --format json emits a fixed field order:
            //   ociVersion, id, pid, status, bundle, rootfs, created
            // "rootfs" is derived from the bundle path and "annotations" is
            // omitted entirely.
            System.out.println(Json.encodeCompact(states.stream().map(s -> {
                java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
                m.put("ociVersion", s.ociVersion);
                m.put("id", s.id);
                m.put("pid", s.pid);
                m.put("status", s.status);
                m.put("bundle", s.bundle);
                m.put("rootfs", s.bundle != null ? s.bundle + "/rootfs" : "");
                m.put("created", s.created);
                return m;
            }).toList()));
            return 0;
        }
        // runc column order: ID PID STATUS BUNDLE CREATED OWNER
        System.out.printf("%-30s %-8s %-10s %-40s %s%n", "ID", "PID", "STATUS", "BUNDLE", "CREATED");
        for (State s : states) {
            System.out.printf("%-30s %-8s %-10s %-40s %s%n",
                    s.id, s.pid == null ? "-" : s.pid,
                    s.status, s.bundle, s.created == null ? "-" : s.created);
        }
        return 0;
    }

    /** Default root for runc/takoyaki. */
    private static boolean isDefaultRoot(String rootPath) {
        return "/run/takoyaki".equals(rootPath) || "/run/runc".equals(rootPath);
    }
}
