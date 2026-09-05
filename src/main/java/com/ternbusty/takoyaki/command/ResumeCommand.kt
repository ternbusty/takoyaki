package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State

object ResumeCommand {

    fun run(rootPath: String, containerId: String): Int {
        try {
            val state = State.load(rootPath, containerId).refreshStatus()
            if (state.statusEnum() != ContainerStatus.RUNNING &&
                state.statusEnum() != ContainerStatus.PAUSED
            ) {
                System.err.println("cannot resume container $containerId that is not paused")
                return 1
            }
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            return 1
        }
        return Freeze.write(rootPath, containerId, "0", "resume")
    }
}
