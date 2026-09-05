package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.logger.Logger
import java.io.IOException
import java.nio.file.Files

/** Shared helper for pause / resume -- writes cgroup.freeze (cgroup v2). */
internal object Freeze {

    fun write(rootPath: String, containerId: String, value: String, op: String): Int {
        val cgroupPath: String = try {
            KontainerConfig.load(rootPath, containerId).cgroupPath
                ?: run {
                    System.err.println("$op failed: container has no cgroupsPath")
                    return 1
                }
        } catch (e: IOException) {
            System.err.println("$op failed: no cgroup recorded for $containerId")
            return 1
        }
        val freeze = Cgroup.dir(cgroupPath).resolve("cgroup.freeze")
        return try {
            Files.writeString(freeze, value)
            Logger.info("$op ok for $containerId")
            0
        } catch (e: IOException) {
            System.err.println("$op failed: ${e.message}")
            1
        }
    }
}
