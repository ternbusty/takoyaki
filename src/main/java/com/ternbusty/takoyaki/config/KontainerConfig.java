package com.ternbusty.takoyaki.config;

import com.ternbusty.takoyaki.util.Json;
import com.ternbusty.takoyaki.util.json.JsonMap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public final class KontainerConfig {
    public String cgroupPath;
    public boolean noNewKeyring;

    public KontainerConfig() {}

    public KontainerConfig(String cgroupPath) {
        this.cgroupPath = cgroupPath;
    }

    public KontainerConfig(String cgroupPath, boolean noNewKeyring) {
        this.cgroupPath = cgroupPath;
        this.noNewKeyring = noNewKeyring;
    }

    public static Path path(String rootPath, String containerId) {
        return Path.of(rootPath, containerId, "config.json");
    }

    public void save(String rootPath, String containerId) throws IOException {
        Path p = path(rootPath, containerId);
        Files.createDirectories(p.getParent());
        Json.writeFile(p, toJson());
    }

    public static KontainerConfig load(String rootPath, String containerId) throws IOException {
        return Json.readFile(path(rootPath, containerId), KontainerConfig::fromJson);
    }

    public static KontainerConfig fromJson(Object node) {
        if (node == null) return null;
        Map<String, Object> o = JsonMap.asObject(node);
        KontainerConfig c = new KontainerConfig();
        c.cgroupPath = JsonMap.str(o, "cgroupPath");
        c.noNewKeyring = JsonMap.boolOr(o, "noNewKeyring", false);
        return c;
    }

    public Object toJson() {
        Map<String, Object> o = JsonMap.obj();
        JsonMap.put(o, "cgroupPath", cgroupPath);
        if (noNewKeyring) JsonMap.put(o, "noNewKeyring", true);
        return o;
    }
}
