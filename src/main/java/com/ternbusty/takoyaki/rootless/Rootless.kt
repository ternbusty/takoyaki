package com.ternbusty.takoyaki.rootless

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Libc

/**
 * Rootless container helpers.
 *
 * When running as a non-root user, only the unprivileged user himself (uid 0 inside
 * the new userns) can be mapped without external help. To map a *range* of uids
 * (e.g. for sub-uids from /etc/subuid), the setuid newuidmap/newgidmap binaries
 * from the shadow-utils package must be invoked because the kernel won't accept
 * /proc/PID/uid_map writes from an unprivileged caller.
 *
 * runc and youki use the same approach.
 */
object Rootless {

    fun isRootless(): Boolean = Libc.geteuid() != 0

    /** Write uid_map for [pid] via newuidmap if available, else fall back to direct write. */
    fun writeUidMap(pid: Int, mappings: List<LinuxIdMapping>?): Boolean =
        writeViaHelper(pid, mappings, "newuidmap")

    fun writeGidMap(pid: Int, mappings: List<LinuxIdMapping>?): Boolean =
        writeViaHelper(pid, mappings, "newgidmap")

    private fun writeViaHelper(pid: Int, mappings: List<LinuxIdMapping>?, helper: String): Boolean {
        if (mappings.isNullOrEmpty()) return true
        val cmd = ArrayList<String>()
        cmd.add(helper)
        cmd.add(pid.toString())
        for (m in mappings) {
            cmd.add(m.containerID.toString())
            cmd.add(m.hostID.toString())
            cmd.add(m.size.toString())
        }
        return try {
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val rc = p.waitFor()
            if (rc != 0) {
                val out = String(p.inputStream.readAllBytes())
                Logger.warn("$helper failed (rc=$rc): $out")
                false
            } else {
                Logger.debug("$helper ok for pid $pid")
                true
            }
        } catch (e: Exception) {
            Logger.debug("$helper not usable: ${e.message}")
            false
        }
    }
}
