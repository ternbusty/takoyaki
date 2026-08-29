package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.hooks.Hooks
import com.ternbusty.takoyaki.ipc.NotifySocket
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.util.JsonCodec
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator

object DeleteCommand {

    fun run(rootPath: String, containerId: String, force: Boolean): Int {
        if (!State.exists(rootPath, containerId)) {
            if (force) {
                // runc compat: --force on non-existent container succeeds
                return 0
            }
            System.err.println("container $containerId does not exist")
            return 1
        }
        val state: State
        try {
            state = State.load(rootPath, containerId).refreshStatus()
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            return 1
        }
        if (!state.statusEnum().canDelete()) {
            if (!force) {
                System.err.println(
                    "cannot delete container $containerId that is not stopped: ${state.status}"
                )
                return 1
            }
            // Unfreeze first if the container is paused, then kill all
            // processes via cgroup (covers host pidns and exec'd workers).
            try {
                val kc = KontainerConfig.load(rootPath, containerId)
                val cgPath = kc.cgroupPath
                if (cgPath != null) {
                    // Unfreeze if frozen (paused containers cannot be killed while frozen)
                    val freeze = Cgroup.dir(cgPath).resolve("cgroup.freeze")
                    if (Files.exists(freeze) && Files.readString(freeze).trim() == "1") {
                        Files.writeString(freeze, "0")
                    }
                    // Kill all processes in cgroup
                    val procs = Cgroup.dir(cgPath).resolve("cgroup.procs")
                    if (Files.exists(procs)) {
                        for (attempt in 0 until 10) {
                            val content = Files.readString(procs).trim()
                            if (content.isEmpty()) break
                            for (line in content.split("\n")) {
                                try {
                                    val pid = line.trim().toInt()
                                    Libc.kill(pid, Constants.SIGKILL)
                                } catch (_: NumberFormatException) {
                                }
                            }
                            Thread.sleep(50)
                        }
                    }
                }
            } catch (e: Exception) {
                Logger.debug("cgroup kill during force delete: ${e.message}")
            }
            val pid = state.pid
            if (pid != null) {
                Libc.kill(pid, Constants.SIGKILL)
            }
        }

        try {
            val kc = KontainerConfig.load(rootPath, containerId)
            if (kc.cgroupPath != null) Cgroup.cleanup(kc.cgroupPath)
        } catch (e: IOException) {
            Logger.debug("no kontainer config or cgroup cleanup skipped: ${e.message}")
        }

        try {
            Files.deleteIfExists(Path.of(NotifySocket.pathFor(containerId)))
        } catch (e: IOException) {
            Logger.warn("failed to remove notify socket: ${e.message}")
        }

        // poststop hook fires in the runtime namespace before we remove the state dir.
        try {
            val spec = JsonCodec.loadFromFile<Spec>(Path.of(state.bundle, "config.json"))
            val hooks = spec?.hooks
            if (hooks != null) Hooks.run(hooks.poststop, state, "poststop")
        } catch (_: IOException) {
            // bundle may already be gone for stopped containers; skip silently
        }

        val dir = State.containerDir(rootPath, containerId)
        return try {
            if (Files.exists(dir)) {
                Files.walk(dir).use { walk ->
                    walk.sorted(Comparator.reverseOrder()).forEach { p ->
                        try {
                            Files.deleteIfExists(p)
                        } catch (_: IOException) {
                        }
                    }
                }
            }
            Logger.info("container $containerId deleted")
            0
        } catch (e: IOException) {
            Logger.error("failed to delete dir: ${e.message}")
            1
        }
    }
}
