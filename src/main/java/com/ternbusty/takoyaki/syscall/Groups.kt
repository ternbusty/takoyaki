package com.ternbusty.takoyaki.syscall

import com.ternbusty.takoyaki.logger.Logger
import java.io.IOException
import java.lang.foreign.Arena
import java.nio.file.Files
import java.nio.file.Path

object Groups {

    fun setAdditional(gids: List<Int>?) {
        if (gids.isNullOrEmpty()) return
        try {
            val s = Files.readString(Path.of("/proc/self/setgroups")).trim()
            if (s == "deny") {
                Logger.warn("setgroups denied in this user namespace, skipping")
                return
            }
        } catch (_: IOException) {
        }

        Arena.ofConfined().use { arena ->
            val arr = IntArray(gids.size) { gids[it] }
            val rc = Libc.setgroups(arena, arr)
            if (rc != 0) {
                Logger.warn("setgroups failed: ${Libc.strerror(Libc.errno())}")
            } else {
                Logger.debug("set ${gids.size} additional groups")
            }
        }
    }
}
