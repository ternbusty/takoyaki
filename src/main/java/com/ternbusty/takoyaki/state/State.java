package com.ternbusty.takoyaki.state;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.util.Json;
import com.ternbusty.takoyaki.util.json.JsonMap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;

public final class State {
    private static final DateTimeFormatter CREATED_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    public String ociVersion;
    public String id;
    public String status;
    public Integer pid;
    public String bundle;
    public Map<String, String> annotations;
    public String created;

    public State() {}

    public State(String ociVersion, String id, ContainerStatus status,
                 Integer pid, String bundle, Map<String, String> annotations, String created) {
        this.ociVersion = ociVersion;
        this.id = id;
        this.status = status.value;
        this.pid = pid;
        this.bundle = bundle;
        this.annotations = annotations;
        this.created = created;
    }

    public ContainerStatus statusEnum() {
        return ContainerStatus.fromString(status);
    }

    public State withStatus(ContainerStatus s) {
        return new State(ociVersion, id, s, pid, bundle, annotations, created);
    }

    public static Path containerDir(String rootPath, String containerId) {
        return Path.of(rootPath, containerId);
    }

    public static Path statePath(String rootPath, String containerId) {
        return containerDir(rootPath, containerId).resolve("state.json");
    }

    public static boolean exists(String rootPath, String containerId) {
        return Files.exists(statePath(rootPath, containerId));
    }

    public static State load(String rootPath, String containerId) throws IOException {
        Path p = statePath(rootPath, containerId);
        Logger.debug("loading state from " + p);
        return Json.readFile(p, State::fromJson);
    }

    public void save(String rootPath) throws IOException {
        Path dir = containerDir(rootPath, id);
        Files.createDirectories(dir);
        Path p = dir.resolve("state.json");
        Logger.debug("saving state to " + p);
        Json.writeFile(p, toJson());
    }

    public static State create(String ociVersion, String containerId,
                               ContainerStatus status, Integer pid, String bundle,
                               Map<String, String> annotations) {
        String created = OffsetDateTime.now(ZoneOffset.UTC).format(CREATED_FORMAT);
        return new State(ociVersion, containerId, status, pid, bundle, annotations, created);
    }

    public State refreshStatus() {
        if (pid != null && isProcessAlive(pid)) return this;
        return statusEnum() == ContainerStatus.STOPPED ? this : withStatus(ContainerStatus.STOPPED);
    }

    private static boolean isProcessAlive(int pid) {
        Path stat = Path.of("/proc", String.valueOf(pid), "stat");
        try {
            String content = Files.readString(stat);
            int lp = content.lastIndexOf(')');
            if (lp < 0 || lp + 2 >= content.length()) return false;
            char st = content.charAt(lp + 2);
            return st != 'Z' && st != 'X';
        } catch (IOException e) {
            return false;
        }
    }

    public static State fromJson(Object node) {
        if (node == null) return null;
        Map<String, Object> o = JsonMap.asObject(node);
        State s = new State();
        s.ociVersion = JsonMap.str(o, "ociVersion");
        s.id = JsonMap.str(o, "id");
        s.status = JsonMap.str(o, "status");
        s.pid = JsonMap.intBoxed(o, "pid");
        s.bundle = JsonMap.str(o, "bundle");
        s.annotations = JsonMap.strMap(o, "annotations");
        s.created = JsonMap.str(o, "created");
        return s;
    }

    public Object toJson() {
        Map<String, Object> o = JsonMap.obj();
        JsonMap.put(o, "ociVersion", ociVersion);
        JsonMap.put(o, "id", id);
        JsonMap.put(o, "status", status);
        JsonMap.put(o, "pid", pid);
        JsonMap.put(o, "bundle", bundle);
        JsonMap.put(o, "annotations", annotations);
        JsonMap.put(o, "created", created);
        return o;
    }
}
