package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.util.JsonCodec
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

        var spec = defaultSpec()
        if (rootless) {
            spec = toRootless(spec)
        }

        return try {
            JsonCodec.saveToFile(configPath, spec)
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
        val defaultCaps = listOf(
            "CAP_AUDIT_WRITE",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE"
        )

        return Spec(
            ociVersion = OCI_VERSION,
            root = Root(path = "rootfs", readonly = true),
            process = Process(
                terminal = true,
                args = listOf("sh"),
                env = listOf(
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "TERM=xterm"
                ),
                cwd = "/",
                noNewPrivileges = true,
                capabilities = LinuxCapabilities(
                    bounding = defaultCaps,
                    effective = defaultCaps,
                    permitted = defaultCaps,
                ),
                rlimits = listOf(
                    POSIXRlimit(type = "RLIMIT_NOFILE", hard = 1024, soft = 1024)
                ),
            ),
            hostname = "takoyaki",
            mounts = defaultMounts(),
            linux = Linux(
                namespaces = listOf("pid", "network", "ipc", "uts", "mount", "cgroup")
                    .map { Namespace(type = it) },
                maskedPaths = listOf(
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
                ),
                readonlyPaths = listOf(
                    "/proc/bus",
                    "/proc/fs",
                    "/proc/irq",
                    "/proc/sys",
                    "/proc/sysrq-trigger"
                ),
                resources = LinuxResources(
                    devices = listOf(
                        LinuxDeviceCgroup(allow = false, access = "rwm")
                    )
                ),
            ),
        )
    }

    private fun defaultMounts(): List<Mount> = listOf(
        Mount(destination = "/proc", source = "proc", type = "proc"),
        Mount(
            destination = "/dev", source = "tmpfs", type = "tmpfs",
            options = listOf("nosuid", "strictatime", "mode=755", "size=65536k"),
        ),
        Mount(
            destination = "/dev/pts", source = "devpts", type = "devpts",
            options = listOf("nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"),
        ),
        Mount(
            destination = "/dev/shm", source = "shm", type = "tmpfs",
            options = listOf("nosuid", "noexec", "nodev", "mode=1777", "size=65536k"),
        ),
        Mount(
            destination = "/dev/mqueue", source = "mqueue", type = "mqueue",
            options = listOf("nosuid", "noexec", "nodev"),
        ),
        Mount(
            destination = "/sys", source = "sysfs", type = "sysfs",
            options = listOf("nosuid", "noexec", "nodev", "ro"),
        ),
        Mount(
            destination = "/sys/fs/cgroup", source = "cgroup", type = "cgroup",
            options = listOf("nosuid", "noexec", "nodev", "relatime", "ro"),
        ),
    )

    /**
     * Adjusts the spec for rootless execution, matching runc's
     * specconv.ToRootless(). Returns a new Spec with rootless
     * adjustments applied.
     */
    private fun toRootless(spec: Spec): Spec {
        val linux = spec.linux ?: return spec

        // Remove network namespace, add user namespace
        val namespaces = (linux.namespaces ?: emptyList())
            .filter { it.type != "network" }
            .let { ns ->
                if (ns.none { it.type == "user" }) {
                    ns + Namespace(type = "user")
                } else {
                    ns
                }
            }

        // UID/GID mappings
        val uidMap = LinuxIdMapping(containerID = 0, hostID = 1000, size = 1)
        val gidMap = LinuxIdMapping(containerID = 0, hostID = 1000, size = 1)

        // Adjust mounts for rootless
        val newMounts = spec.mounts?.map { m ->
            when (m.destination) {
                "/dev/pts" -> {
                    // Remove gid=5 since we might not have that group in rootless
                    m.copy(options = m.options?.filterNot { it.startsWith("gid=") })
                }
                "/sys" -> {
                    // sysfs must be bind-mounted in rootless
                    m.copy(
                        type = "none",
                        source = "/sys",
                        options = listOf("rbind", "nosuid", "noexec", "nodev", "ro"),
                    )
                }
                "/sys/fs/cgroup" -> {
                    // cgroup2 must be bind-mounted in rootless
                    m.copy(
                        type = "none",
                        source = "/sys/fs/cgroup",
                        options = listOf("rbind", "nosuid", "noexec", "nodev", "relatime", "ro"),
                    )
                }
                else -> m
            }
        }

        val newLinux = linux.copy(
            namespaces = namespaces,
            uidMappings = listOf(uidMap),
            gidMappings = listOf(gidMap),
        )

        return spec.copy(
            mounts = newMounts,
            linux = newLinux,
        )
    }
}
