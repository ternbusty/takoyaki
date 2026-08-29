package com.ternbusty.takoyaki.state

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.util.Json
import com.ternbusty.takoyaki.util.json.JsonMap
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

enum class ContainerStatus(val value: String) {
    CREATING("creating"),
    CREATED("created"),
    RUNNING("running"),
    PAUSED("paused"),
    STOPPED("stopped");

    fun canStart(): Boolean = this == CREATED
    fun canKill(): Boolean = this == CREATED || this == RUNNING || this == PAUSED
    fun canDelete(): Boolean = this == STOPPED

    companion object {
        fun fromString(s: String): ContainerStatus =
            entries.firstOrNull { it.value == s }
                ?: throw IllegalArgumentException("Unknown status: $s")
    }
}

class State(
    var ociVersion: String? = null,
    var id: String? = null,
    var status: String? = null,
    var pid: Int? = null,
    var bundle: String? = null,
    var annotations: Map<String, String>? = null,
    var created: String? = null
) {
    constructor(
        ociVersion: String?, id: String?, status: ContainerStatus,
        pid: Int?, bundle: String?, annotations: Map<String, String>?, created: String?
    ) : this(ociVersion, id, status.value, pid, bundle, annotations, created)

    /** Internal transient field set by [load] for frozen-state detection. */
    @Transient
    private var loadedRootPath: String? = null

    fun statusEnum(): ContainerStatus = ContainerStatus.fromString(status ?: "stopped")

    fun withStatus(s: ContainerStatus): State =
        State(ociVersion, id, s, pid, bundle, annotations, created)

    @Throws(IOException::class)
    fun save(rootPath: String) {
        val cid = id ?: throw IOException("cannot save state without container id")
        val dir = containerDir(rootPath, cid)
        Files.createDirectories(dir)
        val p = dir.resolve("state.json")
        Logger.debug("saving state to $p")
        Json.writeFile(p, toJson())
    }

    fun refreshStatus(): State {
        val currentPid = pid
        if (currentPid != null && isProcessAlive(currentPid)) {
            if (isFrozen()) return withStatus(ContainerStatus.PAUSED)
            return this
        }
        return if (statusEnum() == ContainerStatus.STOPPED) this else withStatus(ContainerStatus.STOPPED)
    }

    /**
     * Detect whether this container's cgroup is frozen. Reads the kontainer
     * config to find the cgroup path and then checks cgroup.freeze.
     */
    private fun isFrozen(): Boolean {
        val rootPath = loadedRootPath ?: return false
        return try {
            val cid = id ?: return false
            val kc = com.ternbusty.takoyaki.config.KontainerConfig.load(rootPath, cid)
            val cgroupPath = kc.cgroupPath ?: return false
            val freeze = com.ternbusty.takoyaki.cgroup.Cgroup.dir(cgroupPath)
                .resolve("cgroup.freeze")
            if (!Files.exists(freeze)) return false
            "1" == Files.readString(freeze).trim()
        } catch (e: Exception) {
            false
        }
    }

    fun toJson(): Any {
        val o = JsonMap.obj()
        JsonMap.put(o, "ociVersion", ociVersion)
        JsonMap.put(o, "id", id)
        JsonMap.put(o, "pid", pid)
        JsonMap.put(o, "status", status)
        JsonMap.put(o, "bundle", bundle)
        JsonMap.put(o, "annotations", annotations)
        JsonMap.put(o, "created", created)
        return o
    }

    companion object {
        private val CREATED_FORMAT: DateTimeFormatter =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")

        fun containerDir(rootPath: String, containerId: String): Path =
            Path.of(rootPath, containerId)

        fun statePath(rootPath: String, containerId: String): Path =
            containerDir(rootPath, containerId).resolve("state.json")

        fun exists(rootPath: String, containerId: String): Boolean =
            Files.exists(statePath(rootPath, containerId))

        @Throws(IOException::class)
        fun load(rootPath: String, containerId: String): State {
            val p = statePath(rootPath, containerId)
            Logger.debug("loading state from $p")
            val s = Json.readFile(p, ::fromJson)
                ?: throw IOException("failed to parse state from $p")
            s.loadedRootPath = rootPath
            return s
        }

        fun create(
            ociVersion: String, containerId: String,
            status: ContainerStatus, pid: Int?, bundle: String,
            annotations: Map<String, String>?
        ): State {
            val created = OffsetDateTime.now(ZoneOffset.UTC).format(CREATED_FORMAT)
            return State(ociVersion, containerId, status, pid, bundle, annotations, created)
        }

        private fun isProcessAlive(pid: Int): Boolean {
            val stat = Path.of("/proc", pid.toString(), "stat")
            return try {
                val content = Files.readString(stat)
                val lp = content.lastIndexOf(')')
                if (lp < 0 || lp + 2 >= content.length) return false
                val st = content[lp + 2]
                st != 'Z' && st != 'X'
            } catch (e: IOException) {
                false
            }
        }

        fun fromJson(node: Any?): State? {
            if (node == null) return null
            val o = JsonMap.asObject(node) ?: return null
            val s = State()
            s.ociVersion = JsonMap.str(o, "ociVersion")
            s.id = JsonMap.str(o, "id")
            s.status = JsonMap.str(o, "status")
            s.pid = JsonMap.intBoxed(o, "pid")
            s.bundle = JsonMap.str(o, "bundle")
            @Suppress("UNCHECKED_CAST")
            s.annotations = JsonMap.strMap(o, "annotations") as Map<String, String>?
            s.created = JsonMap.str(o, "created")
            return s
        }
    }
}
