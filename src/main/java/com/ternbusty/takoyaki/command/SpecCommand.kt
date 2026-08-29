package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.util.Json
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * Generates a default OCI runtime-spec `config.json` in the current
 * directory (or the path given by `--bundle`). The output matches
 * `runc spec` so that tooling built against runc (bats integration
 * tests, runtime-tools) works with takoyaki unchanged.
 */
object SpecCommand {

    private const val OCI_VERSION = "1.0.2-dev"

    fun run(args: Array<String>, start: Int): Int {
        var bundle = "."
        var rootless = false
        var i = start
        while (i < args.size) {
            when (args[i]) {
                "-b", "--bundle" -> {
                    if (i + 1 < args.size) bundle = args[++i]
                }
                "--rootless" -> rootless = true
                else -> { /* ignore unknown flags for forward compat */ }
            }
            i++
        }

        val configPath = Path.of(bundle, "config.json")
        if (Files.exists(configPath)) {
            Logger.error("config.json already exists")
            return 1
        }

        val spec = defaultSpec()
        if (rootless) {
            toRootless(spec)
        }

        return try {
            Json.writeFile(configPath, spec.toJson())
            0
        } catch (e: IOException) {
            Logger.error("failed to write config.json: ${e.message}")
            1
        }
    }

    /**
     * Builds the same default spec that `runc spec` produces.
     * See runc/libcontainer/specconv/example.go Example().
     */
    internal fun defaultSpec(): Spec {
        val s = Spec()
        s.ociVersion = OCI_VERSION

        // root
        val root = Spec.Root()
        root.path = "rootfs"
        root.readonly = true
        s.root = root

        // process
        val proc = Spec.Process()
        proc.terminal = true
        proc.args = listOf("sh")
        proc.env = listOf(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm"
        )
        proc.cwd = "/"
        proc.noNewPrivileges = true

        val caps = Spec.LinuxCapabilities()
        val defaultCaps = listOf(
            "CAP_AUDIT_WRITE",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE"
        )
        caps.bounding = defaultCaps
        caps.effective = defaultCaps
        caps.permitted = defaultCaps
        proc.capabilities = caps

        val rlimit = Spec.POSIXRlimit()
        rlimit.type = "RLIMIT_NOFILE"
        rlimit.hard = 1024
        rlimit.soft = 1024
        proc.rlimits = listOf(rlimit)
        s.process = proc

        // hostname
        s.hostname = "takoyaki"

        // mounts
        s.mounts = defaultMounts()

        // linux
        val linux = Spec.Linux()

        // namespaces (always include cgroup namespace for cgroup v2)
        val ns = mutableListOf<Spec.Namespace>()
        for (type in listOf("pid", "network", "ipc", "uts", "mount", "cgroup")) {
            val n = Spec.Namespace()
            n.type = type
            ns.add(n)
        }
        linux.namespaces = ns

        linux.maskedPaths = listOf(
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
        )
        linux.readonlyPaths = listOf(
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger"
        )

        // default device cgroup: deny all
        val deny = Spec.LinuxDeviceCgroup()
        deny.allow = false
        deny.access = "rwm"
        val res = Spec.LinuxResources()
        res.devices = listOf(deny)
        linux.resources = res

        s.linux = linux
        return s
    }

    private fun defaultMounts(): List<Spec.Mount> {
        val mounts = mutableListOf<Spec.Mount>()

        mounts.add(mount("/proc", "proc", "proc", emptyList()))
        mounts.add(mount("/dev", "tmpfs", "tmpfs",
            listOf("nosuid", "strictatime", "mode=755", "size=65536k")))
        mounts.add(mount("/dev/pts", "devpts", "devpts",
            listOf("nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5")))
        mounts.add(mount("/dev/shm", "shm", "tmpfs",
            listOf("nosuid", "noexec", "nodev", "mode=1777", "size=65536k")))
        mounts.add(mount("/dev/mqueue", "mqueue", "mqueue",
            listOf("nosuid", "noexec", "nodev")))
        mounts.add(mount("/sys", "sysfs", "sysfs",
            listOf("nosuid", "noexec", "nodev", "ro")))
        mounts.add(mount("/sys/fs/cgroup", "cgroup", "cgroup",
            listOf("nosuid", "noexec", "nodev", "relatime", "ro")))

        return mounts
    }

    private fun mount(dest: String, source: String, type: String, options: List<String>): Spec.Mount {
        val m = Spec.Mount()
        m.destination = dest
        m.source = source
        m.type = type
        m.options = options.ifEmpty { null }
        return m
    }

    /**
     * Adjusts the spec for rootless execution, matching runc's
     * specconv.ToRootless().
     */
    private fun toRootless(spec: Spec) {
        val linux = spec.linux ?: return

        // Remove network namespace, add user namespace
        val ns = (linux.namespaces ?: emptyList()).toMutableList()
        ns.removeAll { it.type == "network" }
        if (ns.none { it.type == "user" }) {
            val userNs = Spec.Namespace()
            userNs.type = "user"
            ns.add(userNs)
        }
        linux.namespaces = ns

        // UID/GID mappings
        val uidMap = Spec.IdMapping()
        uidMap.containerID = 0
        uidMap.hostID = 1000
        uidMap.size = 1
        linux.uidMappings = listOf(uidMap)

        val gidMap = Spec.IdMapping()
        gidMap.containerID = 0
        gidMap.hostID = 1000
        gidMap.size = 1
        linux.gidMappings = listOf(gidMap)

        // Adjust mounts for rootless
        spec.mounts?.forEach { m ->
            if (m.destination == "/dev/pts") {
                val opts = m.options
                if (opts != null) {
                    // Remove gid=5 since we might not have that group in rootless
                    m.options = opts.toMutableList().apply {
                        removeAll { it.startsWith("gid=") }
                    }
                }
            }
            if (m.destination == "/sys") {
                // sysfs must be bind-mounted in rootless
                m.type = "none"
                m.source = "/sys"
                m.options = listOf("rbind", "nosuid", "noexec", "nodev", "ro")
            }
            if (m.destination == "/sys/fs/cgroup") {
                // cgroup2 must be bind-mounted in rootless
                m.type = "none"
                m.source = "/sys/fs/cgroup"
                m.options = listOf("rbind", "nosuid", "noexec", "nodev", "relatime", "ro")
            }
        }
    }
}
