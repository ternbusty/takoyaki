package com.ternbusty.takoyaki.state

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.util.JsonCodec
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
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

@Serializable
data class State(
    val ociVersion: String? = null,
    val id: String? = null,
    val status: String? = null,
    val pid: Int? = null,
    val bundle: String? = null,
    val annotations: Map<String, String>? = null,
    val created: String? = null,
) {
    @Transient
    private var loadedRootPath: String? = null

    constructor(
        ociVersion: String?, id: String?, status: ContainerStatus,
        pid: Int?, bundle: String?, annotations: Map<String, String>?, created: String?
    ) : this(ociVersion, id, status.value, pid, bundle, annotations, created)

    fun statusEnum(): ContainerStatus = ContainerStatus.fromString(status ?: "stopped")

    fun withStatus(s: ContainerStatus): State = copy(status = s.value)

    @Throws(IOException::class)
    fun save(rootPath: String) {
        val cid = id ?: throw IOException("cannot save state without container id")
        val dir = containerDir(rootPath, cid)
        Files.createDirectories(dir)
        val p = dir.resolve("state.json")
        Logger.debug("saving state to $p")
        JsonCodec.saveToFile(p, this)
    }

    fun refreshStatus(): State {
        val currentPid = pid
        if (currentPid != null && isProcessAlive(currentPid)) {
            if (isFrozen()) return withStatus(ContainerStatus.PAUSED)
            return this
        }
        return if (statusEnum() == ContainerStatus.STOPPED) this else withStatus(ContainerStatus.STOPPED)
    }

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
            val s = JsonCodec.loadFromFile<State>(p)
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
    }
}
