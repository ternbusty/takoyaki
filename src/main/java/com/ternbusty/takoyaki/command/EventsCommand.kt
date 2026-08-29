package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.util.JsonCodec
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardWatchEventKinds
import java.nio.file.WatchService

/**
 * Stream resource-usage statistics from the container's cgroup. Without --stats we
 * fall through to a polling loop similar to `runc events`. The format is JSON Lines.
 */
object EventsCommand {

    fun run(rootPath: String, containerId: String, once: Boolean, interval: String?): Int {
        val cgroupPath: String
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath
                ?: run {
                    System.err.println("no cgroupsPath for container")
                    return 1
                }
        } catch (e: IOException) {
            System.err.println("container $containerId does not exist")
            return 1
        }

        val intervalMs = parseInterval(interval)
        val cg = Cgroup.dir(cgroupPath)

        // Start OOM watcher thread that monitors memory.events for oom_kill.
        val oomWatcher = startOomWatcher(cg, containerId)

        // State directory disappears when the container is deleted; use it
        // as the liveness signal so the loop exits instead of spinning on a
        // removed cgroup path.
        val statePath = Path.of(rootPath, containerId)

        do {
            if (!Files.isDirectory(cg) || !Files.isDirectory(statePath)) break
            val snap = snapshot(cg, containerId)
            println(JsonCodec.encodeCompact(JsonCodec.toJsonElement(snap)))
            System.out.flush()
            if (once) break
            try {
                Thread.sleep(intervalMs)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        } while (true)

        oomWatcher?.interrupt()
        return 0
    }

    /** Monitor memory.events for oom_kill events and emit {"type":"oom"} JSON. */
    private fun startOomWatcher(cg: Path, containerId: String): Thread? {
        val memEvents = cg.resolve("memory.events")
        if (!Files.exists(memEvents)) return null
        val t = Thread({
            var lastOomKill = readOomKillCount(memEvents)
            try {
                cg.fileSystem.newWatchService().use { ws: WatchService ->
                    cg.register(ws, StandardWatchEventKinds.ENTRY_MODIFY)
                    while (!Thread.currentThread().isInterrupted) {
                        val key = ws.take()
                        for (event in key.pollEvents()) {
                            if (event.context().toString() == "memory.events") {
                                val current = readOomKillCount(memEvents)
                                if (current > lastOomKill) {
                                    val oomEvent = linkedMapOf<String, Any>(
                                        "type" to "oom",
                                        "id" to containerId,
                                    )
                                    println(JsonCodec.encodeCompact(JsonCodec.toJsonElement(oomEvent)))
                                    lastOomKill = current
                                }
                            }
                        }
                        key.reset()
                    }
                }
            } catch (_: InterruptedException) {
                // shutting down
            } catch (_: IOException) {
                // memory.events not watchable, give up silently
            }
        }, "oom-watcher")
        t.isDaemon = true
        t.start()
        return t
    }

    /** Read the oom_kill count from cgroup v2 memory.events. */
    private fun readOomKillCount(memEvents: Path): Long =
        readKvFile(memEvents)?.get("oom_kill") ?: 0L

    /** Parse Go-style duration string (5s, 100ms, 1m, etc.) to milliseconds. */
    internal fun parseInterval(s: String?): Long {
        if (s.isNullOrEmpty()) return 5000
        return when {
            s.endsWith("ms") ->
                s.substring(0, s.length - 2).toLong()
            s.endsWith("s") ->
                (s.substring(0, s.length - 1).toDouble() * 1000).toLong()
            s.endsWith("m") ->
                (s.substring(0, s.length - 1).toDouble() * 60000).toLong()
            else ->
                s.toLongOrNull()?.let { it * 1000 } ?: 5000
        }
    }

    private fun snapshot(cg: Path, id: String): Map<String, Any?> {
        val memory = linkedMapOf<String, Any?>(
            "usage" to readKvFile(cg.resolve("memory.current"), singleValue = true),
            "limit" to readLong(cg.resolve("memory.max")),
            "cache" to readLong(cg.resolve("memory.stat"), "file"),
        )
        val raw = readKvFile(cg.resolve("memory.stat"))
        if (raw != null) memory["raw"] = raw

        val cpuUsage = linkedMapOf<String, Any>()
        val cpuStat = readKvFile(cg.resolve("cpu.stat"))
        if (cpuStat != null) {
            cpuUsage["total"] = (cpuStat["usage_usec"] ?: 0L) * 1000
            cpuUsage["user"] = (cpuStat["user_usec"] ?: 0L) * 1000
            cpuUsage["kernel"] = (cpuStat["system_usec"] ?: 0L) * 1000
        }
        val cpu = linkedMapOf<String, Any>("usage" to cpuUsage)
        // PSI data
        readPsi(cg.resolve("cpu.pressure"))?.let { cpu["psi"] = it }

        val pids = linkedMapOf<String, Any?>(
            "current" to readLong(cg.resolve("pids.current")),
            "limit" to readLong(cg.resolve("pids.max")),
        )

        val data = linkedMapOf<String, Any?>(
            "memory" to memory,
            "cpu" to cpu,
            "pids" to pids,
        )

        // hugetlb stats: scan for hugetlb.<pagesize>.current files
        val hugetlb = readHugetlb(cg)
        if (!hugetlb.isNullOrEmpty()) {
            data["hugetlb"] = hugetlb
        }

        return linkedMapOf(
            "type" to "stats",
            "id" to id,
            "data" to data,
        )
    }

    /** Collect hugetlb stats from hugetlb.<pagesize>.{current,max,events} files. */
    private fun readHugetlb(cg: Path): Map<String, Any>? {
        val result = linkedMapOf<String, Any>()
        try {
            Files.newDirectoryStream(cg, "hugetlb.*.current").use { stream ->
                for (p in stream) {
                    // filename: hugetlb.<pagesize>.current
                    val name = p.fileName.toString()
                    val dot1 = name.indexOf('.')
                    val dot2 = name.lastIndexOf('.')
                    if (dot1 < 0 || dot2 <= dot1) continue
                    val pageSize = name.substring(dot1 + 1, dot2)
                    val entry = linkedMapOf<String, Any?>(
                        "usage" to readLong(p),
                        "max" to readLong(cg.resolve("hugetlb.$pageSize.max")),
                        "failcnt" to readLong(cg.resolve("hugetlb.$pageSize.events"), "max"),
                    )
                    result[pageSize] = entry
                }
            }
        } catch (_: IOException) {
        }
        return result
    }

    /** Read a single-value cgroup file as a stats map or as a raw long. */
    private fun readKvFile(p: Path, singleValue: Boolean): Map<String, Long>? {
        if (!singleValue) return readKvFile(p)
        val v = readLong(p) ?: return null
        return linkedMapOf("usage" to v)
    }

    /** Read a specific key from a key-value cgroup file. */
    private fun readLong(p: Path, key: String): Long? =
        readKvFile(p)?.get(key)

    /** Parse PSI pressure file into {some: {avg10,avg60,avg300,total}, full: {...}}. */
    private fun readPsi(p: Path): Map<String, Any>? {
        if (!Files.exists(p)) return null
        return try {
            val psi = linkedMapOf<String, Any>()
            for (line in Files.readAllLines(p)) {
                // Format: some avg10=0.00 avg60=0.00 avg300=0.00 total=0
                val parts = line.split("\\s+".toRegex())
                if (parts.size < 2) continue
                val type = parts[0] // "some" or "full"
                val vals = linkedMapOf<String, Any>()
                for (i in 1 until parts.size) {
                    val kv = parts[i].split("=")
                    if (kv.size == 2) {
                        try {
                            if ("." in kv[1]) {
                                vals[kv[0]] = kv[1].toDouble()
                            } else {
                                vals[kv[0]] = kv[1].toLong()
                            }
                        } catch (_: NumberFormatException) {
                        }
                    }
                }
                psi[type] = vals
            }
            psi.ifEmpty { null }
        } catch (_: IOException) {
            null
        }
    }

    private fun readLong(p: Path): Long? {
        val s = readString(p) ?: return null
        return s.trim().toLongOrNull()
    }

    private fun readString(p: Path): String? =
        try {
            Files.readString(p).trim()
        } catch (_: IOException) {
            null
        }

    private fun readKvFile(p: Path): Map<String, Long>? {
        val kv = linkedMapOf<String, Long>()
        try {
            for (line in Files.readAllLines(p)) {
                val parts = line.split("\\s+".toRegex())
                if (parts.size == 2) {
                    parts[1].toLongOrNull()?.let { kv[parts[0]] = it }
                }
            }
        } catch (_: IOException) {
        }
        return kv
    }
}
