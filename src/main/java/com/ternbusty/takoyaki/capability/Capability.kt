package com.ternbusty.takoyaki.capability

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

object Capability {

    private val NAMES: Array<String> = arrayOf(
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
        "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
        "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
        "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE"
    )

    /** Highest cap id we know about -- the ids are the [NAMES] array indices. */
    private val LAST_CAP: Int = NAMES.size - 1

    private val CAPS: Map<String, Int> =
        NAMES.withIndex().associate { (i, name) -> name to i }

    fun idOf(name: String?): Int = name?.let { CAPS[it] } ?: -1

    fun setKeepCaps() {
        if (Libc.prctl(Constants.PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
            Logger.warn("prctl(PR_SET_KEEPCAPS,1) failed: ${Libc.strerror(Libc.errno())}")
        }
    }

    fun clearKeepCaps() {
        if (Libc.prctl(Constants.PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0) {
            Logger.warn("prctl(PR_SET_KEEPCAPS,0) failed: ${Libc.strerror(Libc.errno())}")
        }
    }

    fun applyBoundingSet(caps: Spec.LinuxCapabilities?) {
        if (caps == null) return
        // When caps is non-null but bounding is null (empty capabilities object),
        // treat as empty set: drop everything from the bounding set.
        val keep: Set<Int> = if (caps.bounding != null) parseSet(caps.bounding) else emptySet()
        for (i in 0..LAST_CAP) {
            if (i !in keep) {
                Libc.prctl(Constants.PR_CAPBSET_DROP, i.toLong(), 0, 0, 0)
            }
        }
        Logger.debug("bounding set applied (${keep.size} kept)")
    }

    fun applyFinalSets(caps: Spec.LinuxCapabilities?) {
        if (caps == null) return
        val eff = mask(caps.effective)
        val per = mask(caps.permitted)
        val inh = mask(caps.inheritable)
        capset(eff, per, inh)

        if (caps.ambient != null) {
            Libc.prctl(Constants.PR_CAP_AMBIENT, Constants.PR_CAP_AMBIENT_CLEAR_ALL.toLong(), 0, 0, 0)
            // The kernel refuses PR_CAP_AMBIENT_RAISE unless the cap is in
            // BOTH permitted AND inheritable. Silently swallowing the EPERM
            // that would result from a spec that says "ambient: [CAP_X]"
            // without also listing X in permitted+inheritable hides the
            // config mistake -- the user asked for X to be preserved across
            // execve, and it silently isn't. Check up front and log which
            // set is missing.
            for (name in caps.ambient) {
                val id = idOf(name)
                if (id < 0) continue
                if (Libc.prctl(Constants.PR_CAP_AMBIENT, Constants.PR_CAP_AMBIENT_RAISE.toLong(), id.toLong(), 0, 0) != 0) {
                    // runc compat: print the same warning logrus emits.
                    val rawErr = Libc.strerror(Libc.errno())
                    val errMsg = rawErr.replaceFirstChar { it.lowercaseChar() }
                    System.err.println("can't raise ambient capability $name: $errMsg")
                }
            }
        }
    }

    private fun parseSet(names: List<String>?): Set<Int> {
        if (names == null) return emptySet()
        val s = mutableSetOf<Int>()
        for (n in names) {
            val id = idOf(n)
            if (id >= 0) {
                s.add(id)
            } else {
                Logger.warn("unknown capability name: $n")
            }
        }
        return s
    }

    private fun mask(names: List<String>?): Long =
        parseSet(names).fold(0L) { m, id -> m or (1L shl id) }

    private fun capset(eff: Long, per: Long, inh: Long) {
        Arena.ofConfined().use { arena ->
            val header = arena.allocate(8)
            header.set(ValueLayout.JAVA_INT, 0, Constants.LINUX_CAPABILITY_VERSION_3)
            header.set(ValueLayout.JAVA_INT, 4, 0)

            val data = arena.allocate((12 * 2).toLong())
            data.set(ValueLayout.JAVA_INT, 0, (eff and 0xFFFFFFFFL).toInt())
            data.set(ValueLayout.JAVA_INT, 4, (per and 0xFFFFFFFFL).toInt())
            data.set(ValueLayout.JAVA_INT, 8, (inh and 0xFFFFFFFFL).toInt())
            data.set(ValueLayout.JAVA_INT, 12, ((eff ushr 32) and 0xFFFFFFFFL).toInt())
            data.set(ValueLayout.JAVA_INT, 16, ((per ushr 32) and 0xFFFFFFFFL).toInt())
            data.set(ValueLayout.JAVA_INT, 20, ((inh ushr 32) and 0xFFFFFFFFL).toInt())

            val rc = Libc.syscall(
                Constants.NR_capset,
                header.address(), data.address(), 0L, 0L, 0L
            )
            if (rc != 0L) {
                Logger.warn("capset failed: ${Libc.strerror(Libc.errno())}")
            } else {
                Logger.debug("capset eff=0x${eff.toULong().toString(16)} per=0x${per.toULong().toString(16)}")
            }
        }
    }
}
