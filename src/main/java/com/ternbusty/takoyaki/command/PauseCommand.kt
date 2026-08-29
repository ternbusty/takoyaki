package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State

object PauseCommand {

    fun run(rootPath: String, containerId: String): Int {
        try {
            val state = State.load(rootPath, containerId).refreshStatus()
            if (state.statusEnum() != ContainerStatus.RUNNING) {
                System.err.println("cannot pause container $containerId that is not running")
                return 1
            }
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            return 1
        }
        return Freeze.write(rootPath, containerId, "1", "pause")
    }
}
