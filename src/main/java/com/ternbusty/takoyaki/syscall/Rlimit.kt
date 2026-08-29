package com.ternbusty.takoyaki.syscall

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*

object Rlimit {

    /** Apply all rlimits except the one named by [excludeType]. */
    fun applyExcept(pid: Int, rlimits: List<POSIXRlimit>?, excludeType: String) {
        if (rlimits.isNullOrEmpty()) return
        val filtered = rlimits.filter { it.type != excludeType }
        apply(pid, filtered)
    }

    /** Apply only the rlimit named by [onlyType]. */
    fun applyOnly(pid: Int, rlimits: List<POSIXRlimit>?, onlyType: String) {
        if (rlimits.isNullOrEmpty()) return
        val filtered = rlimits.filter { it.type == onlyType }
        apply(pid, filtered)
    }

    fun apply(pid: Int, rlimits: List<POSIXRlimit>?) {
        if (rlimits.isNullOrEmpty()) return
        val sc = SyscallHost.current()
        for (r in rlimits) {
            val rtype = r.type
            val resource = resourceId(rtype)
            if (resource < 0) {
                Logger.warn("unknown rlimit type: ${r.type}")
                continue
            }
            val rc = sc.prlimit64(pid, resource, r.soft.toLong(), r.hard.toLong())
            if (rc != 0) {
                Logger.warn("prlimit64 ${r.type} failed: ${sc.strerror(sc.errno())}")
            } else {
                Logger.debug("rlimit ${r.type} soft=${r.soft} hard=${r.hard}")
            }
        }
    }

    private fun resourceId(type: String): Int = when (type) {
        "RLIMIT_CPU" -> Constants.RLIMIT_CPU
        "RLIMIT_FSIZE" -> Constants.RLIMIT_FSIZE
        "RLIMIT_DATA" -> Constants.RLIMIT_DATA
        "RLIMIT_STACK" -> Constants.RLIMIT_STACK
        "RLIMIT_CORE" -> Constants.RLIMIT_CORE
        "RLIMIT_RSS" -> Constants.RLIMIT_RSS
        "RLIMIT_NPROC" -> Constants.RLIMIT_NPROC
        "RLIMIT_NOFILE" -> Constants.RLIMIT_NOFILE
        "RLIMIT_MEMLOCK" -> Constants.RLIMIT_MEMLOCK
        "RLIMIT_AS" -> Constants.RLIMIT_AS
        "RLIMIT_LOCKS" -> Constants.RLIMIT_LOCKS
        "RLIMIT_SIGPENDING" -> Constants.RLIMIT_SIGPENDING
        "RLIMIT_MSGQUEUE" -> Constants.RLIMIT_MSGQUEUE
        "RLIMIT_NICE" -> Constants.RLIMIT_NICE
        "RLIMIT_RTPRIO" -> Constants.RLIMIT_RTPRIO
        "RLIMIT_RTTIME" -> Constants.RLIMIT_RTTIME
        else -> -1
    }
}
