package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.JsonCodec
object StateCommand {

    fun run(rootPath: String, containerId: String): Int {
        return try {
            val s = State.load(rootPath, containerId).refreshStatus()
            println(JsonCodec.encode(s))
            0
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            1
        }
    }
}
