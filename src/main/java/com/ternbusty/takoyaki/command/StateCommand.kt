package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.Json

object StateCommand {

    fun run(rootPath: String, containerId: String): Int {
        return try {
            val s = State.load(rootPath, containerId).refreshStatus()
            println(Json.encode(s.toJson()))
            0
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            1
        }
    }
}
