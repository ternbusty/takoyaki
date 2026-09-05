package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

/**
 * Apply NUMA memory policy via set_mempolicy(2).
 * Called early in the init process, before execve.
 */
object MemPolicy {

    // linux/mempolicy.h constants
    private const val MPOL_DEFAULT = 0
    private const val MPOL_PREFERRED = 1
    private const val MPOL_BIND = 2
    private const val MPOL_INTERLEAVE = 3
    private const val MPOL_LOCAL = 4

    private val MPOL_F_STATIC_NODES = 1 shl 15
    private val MPOL_F_RELATIVE_NODES = 1 shl 14

    /**
     * Validate and apply the memory policy. Throws on invalid config;
     * does nothing when [policy] is null.
     */
    fun apply(policy: LinuxMemoryPolicy?) {
        if (policy == null) return

        val mode = parseMode(policy.mode)
        val flags = parseFlags(policy.flags)

        // Parse node bitmask from the "nodes" string (e.g. "0", "0-3", "0,2").
        var nodeMask: LongArray? = null
        var maxNode = 0
        val nodesStr = policy.nodes
        if (!nodesStr.isNullOrEmpty()) {
            nodeMask = parseNodeMask(nodesStr)
            maxNode = nodeMask.size * 64
        }

        // Validate mode-specific constraints
        if (mode == MPOL_DEFAULT && nodeMask != null && maxNode > 0) {
            // MPOL_DEFAULT requires 0 nodes
            val total = nodeMask.sumOf { it.countOneBits().toLong() }
            if (total > 0) {
                throw RuntimeException(
                    "invalid memory policy: MPOL_DEFAULT mode requires 0 nodes but got $total"
                )
            }
        }

        val modeWithFlags = mode or flags

        Arena.ofConfined().use { arena ->
            var nodemaskAddr = 0L
            if (nodeMask != null && nodeMask.isNotEmpty()) {
                val seg = arena.allocate(nodeMask.size * 8L)
                for (i in nodeMask.indices) {
                    seg.set(ValueLayout.JAVA_LONG, i.toLong() * 8, nodeMask[i])
                }
                nodemaskAddr = seg.address()
            }

            val rc = Libc.syscall(
                Constants.NR_set_mempolicy,
                modeWithFlags.toLong(), nodemaskAddr, maxNode.toLong(), 0L, 0L
            )
            if (rc != 0L) {
                throw RuntimeException("set_mempolicy failed: ${Libc.strerror(Libc.errno())}")
            }
            Logger.debug("set_mempolicy mode=$mode flags=$flags maxnode=$maxNode")
        }
    }

    private fun parseMode(mode: String?): Int {
        if (mode.isNullOrEmpty()) {
            throw RuntimeException("invalid memory policy mode: (empty)")
        }
        return when (mode) {
            "MPOL_DEFAULT" -> MPOL_DEFAULT
            "MPOL_PREFERRED" -> MPOL_PREFERRED
            "MPOL_BIND" -> MPOL_BIND
            "MPOL_INTERLEAVE" -> MPOL_INTERLEAVE
            "MPOL_LOCAL" -> MPOL_LOCAL
            else -> throw RuntimeException("invalid memory policy mode: $mode")
        }
    }

    private fun parseFlags(flags: List<String>?): Int {
        if (flags.isNullOrEmpty()) return 0
        var result = 0
        for (f in flags) {
            result = result or when (f) {
                "MPOL_F_STATIC_NODES" -> MPOL_F_STATIC_NODES
                "MPOL_F_RELATIVE_NODES" -> MPOL_F_RELATIVE_NODES
                else -> throw RuntimeException("invalid memory policy flag: $f")
            }
        }
        return result
    }

    /**
     * Parse a Linux CPU-list style string into a bitmask array.
     * Supports individual nodes ("0,2,4") and ranges ("0-3").
     */
    internal fun parseNodeMask(nodes: String): LongArray {
        val mask = LongArray(16) // up to 1024 nodes
        for (part in nodes.split(",")) {
            val trimmed = part.trim()
            if (trimmed.isEmpty()) continue
            val dash = trimmed.indexOf('-')
            if (dash >= 0) {
                val from: Long
                val to: Long
                try {
                    from = trimmed.substring(0, dash).toLong()
                    to = trimmed.substring(dash + 1).toLong()
                } catch (e: NumberFormatException) {
                    throw RuntimeException("invalid memory policy node: $trimmed")
                }
                if (from < 0 || to < 0 || to > 8192) {
                    throw RuntimeException("invalid memory policy node: $trimmed")
                }
                var n = from
                while (n <= to && n < mask.size * 64L) {
                    mask[(n / 64).toInt()] = mask[(n / 64).toInt()] or (1L shl (n % 64).toInt())
                    n++
                }
            } else {
                val n: Long
                try {
                    n = trimmed.toLong()
                } catch (e: NumberFormatException) {
                    throw RuntimeException("invalid memory policy node: $trimmed")
                }
                if (n < 0 || n > 8192) {
                    throw RuntimeException("invalid memory policy node: $trimmed")
                }
                if (n < mask.size * 64L) {
                    mask[(n / 64).toInt()] = mask[(n / 64).toInt()] or (1L shl (n % 64).toInt())
                }
            }
        }
        // Trim trailing zero longs
        var last = mask.size - 1
        while (last > 0 && mask[last] == 0L) last--
        return mask.copyOf(last + 1)
    }
}
