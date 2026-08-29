package com.ternbusty.takoyaki.config

import com.ternbusty.takoyaki.util.Json
import com.ternbusty.takoyaki.util.json.JsonMap
import java.nio.file.Files
import java.nio.file.Path

class KontainerConfig(
    var cgroupPath: String? = null,
    var noNewKeyring: Boolean = false
) {

    fun save(rootPath: String, containerId: String) {
        val p = path(rootPath, containerId)
        Files.createDirectories(p.parent)
        Json.writeFile(p, toJson())
    }

    fun toJson(): Any {
        val o = JsonMap.obj()
        JsonMap.put(o, "cgroupPath", cgroupPath)
        if (noNewKeyring) JsonMap.put(o, "noNewKeyring", true)
        return o
    }

    companion object {
        fun path(rootPath: String, containerId: String): Path =
            Path.of(rootPath, containerId, "config.json")

        fun load(rootPath: String, containerId: String): KontainerConfig =
            Json.readFile(path(rootPath, containerId), ::fromJson)!!

        fun fromJson(node: Any?): KontainerConfig? {
            if (node == null) return null
            val o = JsonMap.asObject(node) ?: return null
            return KontainerConfig(
                cgroupPath = JsonMap.str(o, "cgroupPath"),
                noNewKeyring = JsonMap.boolOr(o, "noNewKeyring", false)
            )
        }
    }
}
