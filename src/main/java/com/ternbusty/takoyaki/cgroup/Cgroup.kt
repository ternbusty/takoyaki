package com.ternbusty.takoyaki.cgroup

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.stream.Stream

/**
 * Cgroup v2 setup, limit application, and cleanup for container cgroups.
 */
object Cgroup {
    private const val CGROUP_ROOT = "/sys/fs/cgroup"

    /**
     * Controllers that can actually be enabled via cgroup.subtree_control.
     * Used to filter control-file prefixes: "memory.max" names the memory
     * controller, but "cgroup.freeze" (possible via resources.unified) does
     * not name a controller at all.
     */
    private val KNOWN_CONTROLLERS: Set<String> =
        setOf("cpu", "cpuset", "memory", "pids", "io", "hugetlb")

    /**
     * Control files whose write failures should propagate as exceptions during
     * container setup (strict mode). These are the core resource files; an
     * invalid value (e.g. too-small period) should abort create rather than
     * silently succeed.
     */
    private val STRICT_FILES: Set<String> = setOf(
        "cpu.max", "cpu.weight", "cpu.idle",
        "cpuset.cpus", "cpuset.mems",
        "memory.max", "memory.min", "memory.high", "memory.low",
        "memory.swap.max",
        "pids.max"
    )

    /**
     * Resolve an OCI cgroupsPath (with or without a leading '/') to its
     * directory under the cgroup v2 mount.
     */
    fun dir(cgroupPath: String): Path {
        val norm = if (cgroupPath.startsWith("/")) cgroupPath.substring(1) else cgroupPath
        return Path.of(CGROUP_ROOT, norm)
    }

    fun setup(pid: Int, cgroupPath: String?, linux: Linux?) {
        if (cgroupPath == null) return
        val full = dir(cgroupPath)
        try {
            Files.createDirectories(full)
        } catch (e: IOException) {
            Logger.warn("create cgroup dir failed: ${e.message}")
            return
        }

        // Reject if the cgroup already has processes (runc compat: error for
        // a non-empty cgroup to avoid resource conflicts).
        try {
            val procs = Files.readString(full.resolve("cgroup.procs")).trim()
            if (procs.isNotEmpty()) {
                throw RuntimeException("container's cgroup is not empty: $full")
            }
        } catch (_: IOException) {
            // cgroup.procs not readable yet (newly created directory)
        }

        // Reject if the cgroup is already frozen (runc compat).
        try {
            val freeze = Files.readString(full.resolve("cgroup.freeze")).trim()
            if (freeze == "1") {
                throw RuntimeException("container's cgroup unexpectedly frozen")
            }
        } catch (_: IOException) {
            // cgroup.freeze not available (newly created or no freezer)
        }

        // Ensure controllers are enabled in the parent's subtree_control so this cgroup
        // can use them. Walk from root downward.
        enableControllers(full, linux?.resources)

        // Skip pids.max here; it's applied after INIT_READY by
        // MainProcess.applyDeferredPids so the Java init process can create
        // threads needed for GraalVM startup without hitting a low pids limit.
        applyLimits(full, linux?.resources, strict = true, skipPids = true)

        addPid(cgroupPath, pid.toLong())

        // The eBPF device program is NOT attached here. It is deferred to
        // applyDeferredDevices() which MainProcess calls after INIT_READY.
        // The init process needs to create device nodes (mknod) during
        // rootfs setup, and attaching the BPF program before that would
        // block mknod for devices not in the allow list. This matches
        // runc's ordering: cgroupManager.Set (which includes devices) runs
        // after SYNC_READY, not during Apply.
    }

    /**
     * Write pid to cgroup.procs. Returns true on success, false on failure.
     */
    fun addPid(cgroupPath: String?, pid: Long): Boolean {
        if (cgroupPath == null) return true
        val full = dir(cgroupPath)
        return try {
            Files.writeString(full.resolve("cgroup.procs"), pid.toString())
            Logger.debug("added pid $pid to cgroup $full")
            true
        } catch (e: IOException) {
            Logger.warn("adding pid $pid to cgroups $full failed: ${e.message}")
            false
        }
    }

    /**
     * Read /proc/pid/cgroup and return the v2 cgroup path (the part after
     * "0::"). Returns null if unreadable.
     */
    fun readProcessCgroup(pid: Int): String? {
        try {
            val content = Files.readString(Path.of("/proc/$pid/cgroup"))
            for (line in content.split("\n")) {
                if (line.startsWith("0::")) {
                    return line.substring(3)
                }
            }
        } catch (e: IOException) {
            Logger.debug("read /proc/$pid/cgroup failed: ${e.message}")
        }
        return null
    }

    private fun enableControllers(full: Path, r: LinuxResources?) {
        // runc compat: enable ALL available controllers in the parent's
        // subtree_control, not just the ones we plan to write. The container
        // might use controllers internally (e.g. creating subcgroups and
        // enabling controllers for them).
        val needed = linkedSetOf<String>()
        // First, collect controllers from planned writes.
        for ((file, _) in plannedWrites(r)) {
            val dot = file.indexOf('.')
            if (dot > 0) {
                val ctrl = file.substring(0, dot)
                if (ctrl in KNOWN_CONTROLLERS) needed.add(ctrl)
            }
        }
        // Also enable any controllers that are available in the parent but
        // not yet in subtree_control. This matches runc's behaviour of
        // propagating all available controllers to the container's cgroup.
        try {
            val parentCtrl = full.parent?.resolve("cgroup.controllers")
            if (parentCtrl != null && Files.exists(parentCtrl)) {
                val available = Files.readString(parentCtrl).trim()
                for (ctrl in available.split("\\s+".toRegex())) {
                    if (ctrl.isNotEmpty() && ctrl in KNOWN_CONTROLLERS) {
                        needed.add(ctrl)
                    }
                }
            }
        } catch (e: IOException) {
            Logger.debug("read parent cgroup.controllers: ${e.message}")
        }
        if (needed.isEmpty()) return
        // Walk up from full to CGROUP_ROOT to enable controllers in subtree_control
        val root = Path.of(CGROUP_ROOT)
        val chain = mutableListOf<Path>()
        var cur = full.parent
        while (cur != null && cur.startsWith(root)) {
            chain.add(0, cur)
            if (cur == root) break
            cur = cur.parent
        }
        for (p in chain) {
            val sc = p.resolve("cgroup.subtree_control")
            for (ctrl in needed) {
                try {
                    Files.writeString(sc, "+$ctrl")
                } catch (_: IOException) {
                }
            }
        }
    }

    /**
     * Re-apply resource limits to an existing cgroup (e.g. via `update`).
     * Also enables any new controllers required by the update.
     */
    fun applyLimitsOnly(cgroupPath: String, r: LinuxResources?) {
        val full = dir(cgroupPath)
        enableControllers(full, r)
        applyLimits(full, r)
        // Update the eBPF device cgroup program when the update payload
        // includes device rules. Without this, "runc update" with a new
        // device policy would silently leave the old BPF program in place.
        if (r != null && !r.devices.isNullOrEmpty()) {
            DeviceCgroup.apply(cgroupPath, r.devices)
        }
    }

    private fun applyLimits(
        full: Path,
        r: LinuxResources?,
        strict: Boolean = false,
        skipPids: Boolean = false
    ) {
        if (r == null) return
        // Realtime scheduling limits are a cgroup v1 concept — v2 removed
        // cpu.rt_period_us / cpu.rt_runtime_us entirely. Silently ignoring
        // the field would hide a genuine spec violation from the user;
        // surface it so they at least see it in the logs.
        val cpuRT = r.cpu
        if (cpuRT != null && (cpuRT.realtimePeriod != null || cpuRT.realtimeRuntime != null)) {
            Logger.warn(
                "cpu.realtimePeriod / realtimeRuntime are not supported" +
                    " on cgroup v2; ignoring"
            )
        }
        for ((key, value) in plannedWrites(r)) {
            if (skipPids && key == "pids.max") continue
            if (strict && key in STRICT_FILES) {
                writeRequired(full.resolve(key), value)
            } else {
                writeIfPossible(full.resolve(key), value)
            }
        }
    }

    /**
     * Apply deferred pids.max to an already-configured cgroup. Called from
     * MainProcess after INIT_READY so the Java init process (which needs
     * multiple threads for GraalVM's internal machinery) has already
     * finished initialization. Without this deferral, a low pids.max value
     * (e.g. 1 from pids.limit=0) would prevent the init from starting.
     */
    fun applyDeferredPids(cgroupPath: String?, r: LinuxResources?) {
        if (cgroupPath == null || r == null) return
        val full = dir(cgroupPath)
        for ((key, value) in plannedWrites(r)) {
            if (key == "pids.max") {
                writeIfPossible(full.resolve("pids.max"), value)
                Logger.debug("deferred pids.max=$value")
            }
        }
    }

    /**
     * Attach the eBPF device cgroup program after the init process has
     * finished rootfs setup. Called from MainProcess after INIT_READY.
     * The init must create device nodes (mknod) during rootfs setup, and
     * an early BPF attachment would block mknod for devices not in the
     * allow list. This mirrors runc's ordering where cgroupManager.Set
     * (including device BPF) runs after SYNC_READY.
     */
    fun applyDeferredDevices(cgroupPath: String?, r: LinuxResources?) {
        if (cgroupPath == null || r == null || r.devices.isNullOrEmpty()) return
        DeviceCgroup.apply(cgroupPath, r.devices)
    }

    /**
     * The control-file writes derived from the spec resources, in application
     * order. Drives both applyLimits (the writes themselves) and
     * enableControllers (the controller set). resources.unified entries come
     * last so they can override the strongly typed fields if the same file
     * was set both ways.
     */
    private fun plannedWrites(r: LinuxResources?): List<Map.Entry<String, String>> {
        val writes = mutableListOf<Map.Entry<String, String>>()
        if (r == null) return writes
        val memory = r.memory
        if (memory != null) {
            val limit = memory.limit
            if (limit != null) writes.add(
                java.util.AbstractMap.SimpleEntry(
                    "memory.max",
                    if (limit == -1L) "max" else limit.toString()
                )
            )
            val swapVal = memory.swap
            if (swapVal != null && limit != null) {
                val swap = if (swapVal == -1L || limit == -1L) -1L
                else swapVal - limit
                writes.add(
                    java.util.AbstractMap.SimpleEntry(
                        "memory.swap.max",
                        if (swap == -1L) "max" else swap.toString()
                    )
                )
            }
            val reservation = memory.reservation
            if (reservation != null) writes.add(
                java.util.AbstractMap.SimpleEntry(
                    "memory.low",
                    if (reservation == -1L) "max" else reservation.toString()
                )
            )
        }
        val cpu = r.cpu
        if (cpu != null) {
            if (!cpu.cpus.isNullOrEmpty()) {
                writes.add(java.util.AbstractMap.SimpleEntry("cpuset.cpus", cpu.cpus))
            }
            if (!cpu.mems.isNullOrEmpty()) {
                writes.add(java.util.AbstractMap.SimpleEntry("cpuset.mems", cpu.mems))
            }
            val shares = cpu.shares
            if (shares != null && shares > 0) {
                val w = convertSharesToWeight(shares)
                writes.add(java.util.AbstractMap.SimpleEntry("cpu.weight", w.toString()))
            }
            val quota = cpu.quota
            val period = cpu.period
            if (quota != null || period != null) {
                val q = if (quota == null || quota <= 0) "max" else quota.toString()
                val p = if (period == null) "100000" else period.toString()
                writes.add(java.util.AbstractMap.SimpleEntry("cpu.max", "$q $p"))
            }
            // cpu.max.burst is a separate control file since Linux 5.14.
            // Writing before the kernel supports it just fails with ENOENT
            // and writeIfPossible logs at warn — acceptable.
            val burst = cpu.burst
            if (burst != null && burst >= 0) {
                writes.add(java.util.AbstractMap.SimpleEntry("cpu.max.burst", burst.toString()))
            }
            // cpu.idle non-zero moves the cgroup to SCHED_IDLE. Linux 5.15+.
            val idle = cpu.idle
            if (idle != null) {
                writes.add(java.util.AbstractMap.SimpleEntry("cpu.idle", idle.toString()))
            }
        }
        val pids = r.pids
        if (pids != null) {
            val lim = pids.limit
            when {
                lim == null -> {}
                lim == -1L ->
                    writes.add(java.util.AbstractMap.SimpleEntry("pids.max", "max"))
                lim == 0L ->
                    writes.add(java.util.AbstractMap.SimpleEntry("pids.max", "1"))
                lim > 0 ->
                    writes.add(java.util.AbstractMap.SimpleEntry("pids.max", lim.toString()))
            }
        }
        // hugepageLimits: each entry lands in its own hugetlb.<size>.max file.
        // Runc uses the same pageSize→filename mapping.
        if (r.hugepageLimits != null) {
            for (h in r.hugepageLimits) {
                writes.add(
                    java.util.AbstractMap.SimpleEntry("hugetlb.${h.pageSize}.max", h.limit.toString())
                )
            }
        }
        val blockIO = r.blockIO
        if (blockIO != null) {
            appendBlockIO(writes, blockIO)
        }
        // Unified pass-through: any arbitrary control-file the spec author
        // named gets written verbatim. Multi-line values (e.g. "io.max" with
        // multiple per-device entries separated by newlines) are split into
        // one write per line, since the kernel cgroup interface only processes
        // one line per write() call for most files.
        if (r.unified != null) {
            for ((key, value) in r.unified) {
                if ("\n" in value) {
                    for (line in value.split("\n")) {
                        val trimmed = line.trim()
                        if (trimmed.isNotEmpty()) {
                            writes.add(java.util.AbstractMap.SimpleEntry(key, trimmed))
                        }
                    }
                } else {
                    writes.add(java.util.AbstractMap.SimpleEntry(key, value))
                }
            }
        }
        return writes
    }

    /**
     * Emit cgroup v2 io.* files from an OCI blockIO block.
     *
     * OCI's blockIO is a v1-era shape (weight + throttleRead/Write*), so we
     * translate each into its v2 equivalent:
     *   weight                 -> io.weight (unqualified, default for the cgroup)
     *   throttleRead/WriteBps  -> io.max "major:minor rbps=... wbps=..."
     *   throttleRead/WriteIOPS -> io.max "major:minor riops=... wiops=..."
     * Multiple entries for the same major:minor get merged so the kernel
     * doesn't clobber a previous write.
     */
    private fun appendBlockIO(writes: MutableList<Map.Entry<String, String>>, io: LinuxBlockIO) {
        val weight = io.weight
        if (weight != null && weight > 0) {
            writes.add(java.util.AbstractMap.SimpleEntry("io.weight", "default $weight"))
        }
        val perDevice = linkedMapOf<String, StringBuilder>()
        appendThrottle(perDevice, io.throttleReadBpsDevice, "rbps")
        appendThrottle(perDevice, io.throttleWriteBpsDevice, "wbps")
        appendThrottle(perDevice, io.throttleReadIOPSDevice, "riops")
        appendThrottle(perDevice, io.throttleWriteIOPSDevice, "wiops")
        for ((dev, sb) in perDevice) {
            writes.add(java.util.AbstractMap.SimpleEntry("io.max", "$dev ${sb.toString().trim()}"))
        }
    }

    private fun appendThrottle(
        perDevice: MutableMap<String, StringBuilder>,
        devs: List<LinuxThrottleDevice>?,
        key: String
    ) {
        if (devs == null) return
        for (d in devs) {
            if (d.major == null || d.minor == null || d.rate == null) continue
            val dev = "${d.major}:${d.minor}"
            perDevice.getOrPut(dev) { StringBuilder() }
                .append(key).append('=').append(d.rate).append(' ')
        }
    }

    private fun writeRequired(p: Path, v: String) {
        try {
            Files.writeString(p, v)
            Logger.debug("set ${p.fileName}=$v")
        } catch (e: IOException) {
            throw RuntimeException("unable to set ${p.fileName} to \"$v\": ${e.message}")
        }
    }

    private fun writeIfPossible(p: Path, v: String) {
        try {
            Files.writeString(p, v)
            Logger.debug("set ${p.fileName}=$v")
        } catch (e: IOException) {
            Logger.warn("write $p ($v): ${e.message}")
        }
    }

    fun cleanup(cgroupPath: String?) {
        if (cgroupPath == null) return
        val full = dir(cgroupPath)
        if (!Files.exists(full)) return

        // Kill all processes in this cgroup tree (including subcgroups).
        killCgroupTree(full)

        // Wait for all processes to actually exit from the cgroup. The kernel
        // needs time to reap killed processes, and they must disappear from
        // cgroup.procs before rmdir can succeed.
        waitForEmpty(full)

        // Remove subcgroup directories bottom-up, then the main directory.
        // Subcgroups must be removed before the parent (kernel requirement).
        try {
            removeSubcgroups(full)
        } catch (e: IOException) {
            Logger.debug("subcgroup cleanup: ${e.message}")
        }

        // rmdir(2) on a cgroup v2 directory returns EBUSY ("Device or resource
        // busy") even briefly after the cgroup empties — the kernel runs an
        // async tear-down (cgroup_destroy_locked schedules work). Polling
        // cgroup.procs isn't enough to gate rmdir; we need to retry rmdir
        // itself. runc does the same in libcontainer/cgroups/fs2.
        retryRmdir(full)
    }

    /**
     * Send SIGKILL to every process in the cgroup tree rooted at [dir].
     * Uses cgroup.kill (Linux 5.14+) where available, falling back to reading
     * cgroup.procs.
     */
    private fun killCgroupTree(dir: Path) {
        // Try cgroup.kill first (applies to subtree)
        try {
            Files.writeString(dir.resolve("cgroup.kill"), "1")
            return
        } catch (_: IOException) {
        }

        // Fallback: iterate subcgroups and kill manually
        try {
            Files.list(dir).use { children: Stream<Path> ->
                children.filter { Files.isDirectory(it) }.forEach { killCgroupTree(it) }
            }
        } catch (_: IOException) {
        }
        try {
            val procs = Files.readString(dir.resolve("cgroup.procs")).trim()
            if (procs.isNotEmpty()) {
                for (line in procs.split("\n")) {
                    try {
                        val pid = line.trim().toInt()
                        Libc.kill(pid, Constants.SIGKILL)
                    } catch (_: NumberFormatException) {
                    }
                }
            }
        } catch (_: IOException) {
        }
    }

    /**
     * Recursively remove subcgroup directories (depth-first). Each subcgroup is
     * removed with retryRmdir to handle the async kernel teardown. Leaves the
     * top-level [dir] in place for the caller to remove.
     */
    @Throws(IOException::class)
    private fun removeSubcgroups(dir: Path) {
        Files.list(dir).use { children: Stream<Path> ->
            for (child in children.toList()) {
                if (Files.isDirectory(child) && !Files.isSymbolicLink(child)) {
                    removeSubcgroups(child)
                    retryRmdir(child)
                }
            }
        }
    }

    /**
     * Wait for cgroup.procs (and children's) to become empty after a kill.
     * Gives the kernel up to 5 seconds for processes to be reaped.
     */
    private fun waitForEmpty(dir: Path) {
        val deadlineNs = System.nanoTime() + 5_000_000_000L
        while (System.nanoTime() < deadlineNs) {
            if (isTreeEmpty(dir)) return
            try {
                Thread.sleep(10)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
        Logger.debug("cgroup tree not fully empty after 5s: $dir")
    }

    /** Check if cgroup.procs is empty in this dir and all subdirectories. */
    private fun isTreeEmpty(dir: Path): Boolean {
        try {
            val procs = Files.readString(dir.resolve("cgroup.procs")).trim()
            if (procs.isNotEmpty()) return false
        } catch (_: IOException) {
            return true // can't read → treat as empty
        }
        try {
            Files.list(dir).use { children: Stream<Path> ->
                for (child in children.toList()) {
                    if (Files.isDirectory(child) && !Files.isSymbolicLink(child)) {
                        if (!isTreeEmpty(child)) return false
                    }
                }
            }
        } catch (_: IOException) {
            // can't list children → ok
        }
        return true
    }

    /** Retry rmdir with back-off for up to 5 seconds. */
    private fun retryRmdir(dir: Path) {
        var last: IOException? = null
        val deadlineNs = System.nanoTime() + 5_000_000_000L
        while (System.nanoTime() < deadlineNs) {
            try {
                Files.delete(dir)
                Logger.debug("cgroup dir removed: $dir")
                return
            } catch (_: java.nio.file.NoSuchFileException) {
                return
            } catch (e: IOException) {
                last = e
                try {
                    Thread.sleep(20)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
        }
        Logger.warn("cgroup cleanup failed ($dir): ${last?.message ?: "deadline elapsed"}")
    }

    /**
     * Convert cgroup v1 CPU shares to cgroup v2 weight using the same
     * logarithmic formula as runc's `ConvertCPUSharesToCgroupV2Value`.
     * cgroup v1 shares (2..262144) are on an exponential scale, while v2
     * weights (1..10000) are linear.  A naive linear interpolation would
     * compress the low end; this log-based conversion preserves proportional
     * relationships.
     */
    internal fun convertSharesToWeight(shares: Long): Long {
        if (shares == 0L) return 0
        if (shares <= 2) return 1
        if (shares >= 262144) return 10000
        val l = Math.log(shares.toDouble()) / Math.log(2.0)
        val exponent = (l * l + 125.0 * l) / 612.0 - 7.0 / 34.0
        return (Math.pow(10.0, exponent) + 0.99).toLong()
    }
}
