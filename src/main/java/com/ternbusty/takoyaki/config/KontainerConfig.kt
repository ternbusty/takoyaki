package com.ternbusty.takoyaki.config

import com.ternbusty.takoyaki.util.JsonCodec
import kotlinx.serialization.Serializable
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

@Serializable
data class KontainerConfig(
    val cgroupPath: String? = null,
    val noNewKeyring: Boolean = false,
) {
    fun save(rootPath: String, containerId: String) {
        val p = path(rootPath, containerId)
        Files.createDirectories(p.parent)
        JsonCodec.saveToFile(p, this)
    }

    companion object {
        fun path(rootPath: String, containerId: String): Path =
            Path.of(rootPath, containerId, "config.json")

        fun load(rootPath: String, containerId: String): KontainerConfig =
            JsonCodec.loadFromFile(path(rootPath, containerId))
    }
}
