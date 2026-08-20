package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.util.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates a default OCI runtime-spec {@code config.json} in the current
 * directory (or the path given by {@code --bundle}). The output matches
 * {@code runc spec} so that tooling built against runc (bats integration
 * tests, runtime-tools) works with takoyaki unchanged.
 */
public final class SpecCommand {
    private SpecCommand() {}

    private static final String OCI_VERSION = "1.0.2-dev";

    public static int run(String[] args, int start) {
        String bundle = ".";
        boolean rootless = false;
        for (int i = start; i < args.length; i++) {
            switch (args[i]) {
                case "-b", "--bundle" -> {
                    if (i + 1 < args.length) bundle = args[++i];
                }
                case "--rootless" -> rootless = true;
                default -> {
                    // ignore unknown flags for forward compat
                }
            }
        }

        Path configPath = Path.of(bundle, "config.json");
        if (Files.exists(configPath)) {
            Logger.error("config.json already exists");
            return 1;
        }

        Spec spec = defaultSpec();
        if (rootless) {
            toRootless(spec);
        }

        try {
            Json.writeFile(configPath, spec.toJson());
            return 0;
        } catch (IOException e) {
            Logger.error("failed to write config.json: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Builds the same default spec that {@code runc spec} produces.
     * See runc/libcontainer/specconv/example.go Example().
     */
    static Spec defaultSpec() {
        Spec s = new Spec();
        s.ociVersion = OCI_VERSION;

        // root
        var root = new Spec.Root();
        root.path = "rootfs";
        root.readonly = true;
        s.root = root;

        // process
        var proc = new Spec.Process();
        proc.terminal = true;
        proc.args = List.of("sh");
        proc.env = List.of(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "TERM=xterm"
        );
        proc.cwd = "/";
        proc.noNewPrivileges = true;

        var caps = new Spec.LinuxCapabilities();
        List<String> defaultCaps = List.of(
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
        );
        caps.bounding = defaultCaps;
        caps.effective = defaultCaps;
        caps.permitted = defaultCaps;
        proc.capabilities = caps;

        var rlimit = new Spec.POSIXRlimit();
        rlimit.type = "RLIMIT_NOFILE";
        rlimit.hard = 1024;
        rlimit.soft = 1024;
        proc.rlimits = List.of(rlimit);
        s.process = proc;

        // hostname
        s.hostname = "takoyaki";

        // mounts
        s.mounts = defaultMounts();

        // linux
        var linux = new Spec.Linux();

        // namespaces (always include cgroup namespace for cgroup v2)
        var ns = new ArrayList<Spec.Namespace>();
        for (String type : List.of("pid", "network", "ipc", "uts", "mount", "cgroup")) {
            var n = new Spec.Namespace();
            n.type = type;
            ns.add(n);
        }
        linux.namespaces = ns;

        linux.maskedPaths = List.of(
                "/proc/acpi",
                "/proc/asound",
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/timer_list",
                "/proc/timer_stats",
                "/proc/sched_debug",
                "/sys/firmware",
                "/proc/scsi"
        );
        linux.readonlyPaths = List.of(
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger"
        );

        // default device cgroup: deny all
        var deny = new Spec.LinuxDeviceCgroup();
        deny.allow = false;
        deny.access = "rwm";
        var res = new Spec.LinuxResources();
        res.devices = List.of(deny);
        linux.resources = res;

        s.linux = linux;
        return s;
    }

    private static List<Spec.Mount> defaultMounts() {
        List<Spec.Mount> mounts = new ArrayList<>();

        mounts.add(mount("/proc", "proc", "proc", List.of()));
        mounts.add(mount("/dev", "tmpfs", "tmpfs",
                List.of("nosuid", "strictatime", "mode=755", "size=65536k")));
        mounts.add(mount("/dev/pts", "devpts", "devpts",
                List.of("nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5")));
        mounts.add(mount("/dev/shm", "shm", "tmpfs",
                List.of("nosuid", "noexec", "nodev", "mode=1777", "size=65536k")));
        mounts.add(mount("/dev/mqueue", "mqueue", "mqueue",
                List.of("nosuid", "noexec", "nodev")));
        mounts.add(mount("/sys", "sysfs", "sysfs",
                List.of("nosuid", "noexec", "nodev", "ro")));
        mounts.add(mount("/sys/fs/cgroup", "cgroup", "cgroup",
                List.of("nosuid", "noexec", "nodev", "relatime", "ro")));

        return mounts;
    }

    private static Spec.Mount mount(String dest, String source, String type, List<String> options) {
        var m = new Spec.Mount();
        m.destination = dest;
        m.source = source;
        m.type = type;
        m.options = options.isEmpty() ? null : options;
        return m;
    }

    /**
     * Adjusts the spec for rootless execution, matching runc's
     * specconv.ToRootless().
     */
    private static void toRootless(Spec spec) {
        if (spec.linux == null) return;

        // Remove network namespace, add user namespace
        var ns = new ArrayList<>(spec.linux.namespaces);
        ns.removeIf(n -> "network".equals(n.type));
        boolean hasUser = ns.stream().anyMatch(n -> "user".equals(n.type));
        if (!hasUser) {
            var userNs = new Spec.Namespace();
            userNs.type = "user";
            ns.add(userNs);
        }
        spec.linux.namespaces = ns;

        // UID/GID mappings
        var uidMap = new Spec.IdMapping();
        uidMap.containerID = 0;
        uidMap.hostID = 1000;
        uidMap.size = 1;
        spec.linux.uidMappings = List.of(uidMap);

        var gidMap = new Spec.IdMapping();
        gidMap.containerID = 0;
        gidMap.hostID = 1000;
        gidMap.size = 1;
        spec.linux.gidMappings = List.of(gidMap);

        // Adjust mounts for rootless
        if (spec.mounts != null) {
            for (var m : spec.mounts) {
                if ("/dev/pts".equals(m.destination) && m.options != null) {
                    // Remove gid=5 since we might not have that group in rootless
                    m.options = new ArrayList<>(m.options);
                    m.options.removeIf(o -> o.startsWith("gid="));
                }
                if ("/sys".equals(m.destination)) {
                    // sysfs must be bind-mounted in rootless
                    m.type = "none";
                    m.source = "/sys";
                    m.options = List.of("rbind", "nosuid", "noexec", "nodev", "ro");
                }
                if ("/sys/fs/cgroup".equals(m.destination)) {
                    // cgroup2 must be bind-mounted in rootless
                    m.type = "none";
                    m.source = "/sys/fs/cgroup";
                    m.options = List.of("rbind", "nosuid", "noexec", "nodev", "relatime", "ro");
                }
            }
        }
    }
}
