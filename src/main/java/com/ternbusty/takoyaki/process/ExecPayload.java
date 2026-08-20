package com.ternbusty.takoyaki.process;

import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.util.json.JsonMap;

import java.util.Map;

/**
 * Everything the {@code __exec__} process needs, serialized by ExecCommand
 * into the payload socket. The exec side cannot re-read config.json itself:
 * after setns(mnt) the bundle path no longer resolves, so the host side
 * snapshots the effective process document (and the container's seccomp
 * profile) before the namespace transition.
 */
public final class ExecPayload {
    public String containerId;
    public String bundle;
    public String ociVersion;
    public Spec.Process process;
    public Spec.LinuxSeccomp seccomp;
    public Spec.MemoryPolicy memoryPolicy;
    public int preserveFds;

    public static ExecPayload fromJson(Object node) {
        if (node == null) return null;
        Map<String, Object> o = JsonMap.asObject(node);
        ExecPayload p = new ExecPayload();
        p.containerId = JsonMap.str(o, "containerId");
        p.bundle = JsonMap.str(o, "bundle");
        p.ociVersion = JsonMap.str(o, "ociVersion");
        p.process = Spec.Process.fromJson(o.get("process"));
        p.seccomp = Spec.LinuxSeccomp.fromJson(o.get("seccomp"));
        p.memoryPolicy = Spec.MemoryPolicy.fromJson(o.get("memoryPolicy"));
        p.preserveFds = JsonMap.intOr(o, "preserveFds", 0);
        return p;
    }

    public Object toJson() {
        Map<String, Object> o = JsonMap.obj();
        JsonMap.put(o, "containerId", containerId);
        JsonMap.put(o, "bundle", bundle);
        JsonMap.put(o, "ociVersion", ociVersion);
        JsonMap.put(o, "process", process == null ? null : process.toJson());
        JsonMap.put(o, "seccomp", seccomp == null ? null : seccomp.toJson());
        if (memoryPolicy != null) JsonMap.put(o, "memoryPolicy", memoryPolicy.toJson());
        if (preserveFds > 0) JsonMap.put(o, "preserveFds", preserveFds);
        return o;
    }
}
