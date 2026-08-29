package com.ternbusty.takoyaki.syscall

import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.syscall.RecordingSyscalls.PrlimitCall
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.function.IntSupplier

class RlimitTest {

    private fun r(type: String, soft: Long, hard: Long): Spec.POSIXRlimit {
        val p = Spec.POSIXRlimit()
        p.type = type
        p.soft = soft
        p.hard = hard
        return p
    }

    @Test
    fun nullListDoesNothing() {
        val rec = RecordingSyscalls()
        SyscallHost.install(rec).use {
            Rlimit.apply(123, null)
        }
        assertTrue(rec.prlimitCalls().isEmpty())
    }

    @Test
    fun emptyListDoesNothing() {
        val rec = RecordingSyscalls()
        SyscallHost.install(rec).use {
            Rlimit.apply(123, emptyList())
        }
        assertTrue(rec.prlimitCalls().isEmpty())
    }

    @Test
    fun eachKnownTypeRoutesToTheRightResourceId() {
        // OCI process.rlimits is keyed by RLIMIT_* strings. We translate them
        // to the kernel's `resource` enum and call prlimit64. This test pins
        // the (string -> kernel id) table. Getting any one wrong would break
        // runtime-tools' process_rlimits assertions silently.
        val rec = RecordingSyscalls()
        SyscallHost.install(rec).use {
            Rlimit.apply(7777, listOf(
                r("RLIMIT_NOFILE", 3000, 4000),
                r("RLIMIT_AS", 1L shl 30, 2L shl 30),
                r("RLIMIT_STACK", 9L shl 30, 10L shl 30),
                r("RLIMIT_CPU", 60, 120),
                r("RLIMIT_CORE", 3L shl 30, 4L shl 30)
            ))
        }

        val calls = rec.prlimitCalls()
        assertEquals(5, calls.size)
        assertEquals(PrlimitCall(7777, Constants.RLIMIT_NOFILE, 3000L, 4000L), calls[0])
        assertEquals(PrlimitCall(7777, Constants.RLIMIT_AS, 1L shl 30, 2L shl 30), calls[1])
        assertEquals(PrlimitCall(7777, Constants.RLIMIT_STACK, 9L shl 30, 10L shl 30), calls[2])
        assertEquals(PrlimitCall(7777, Constants.RLIMIT_CPU, 60L, 120L), calls[3])
        assertEquals(PrlimitCall(7777, Constants.RLIMIT_CORE, 3L shl 30, 4L shl 30), calls[4])
    }

    @Test
    fun unknownRlimitTypeIsSkippedNotFatal() {
        // Mix a known type with a garbage one. The known one must still go
        // through and the unknown must NOT raise.
        val rec = RecordingSyscalls()
        SyscallHost.install(rec).use {
            assertDoesNotThrow {
                Rlimit.apply(7777, listOf(
                    r("RLIMIT_NOFILE", 100, 200),
                    r("RLIMIT_BOGUS", 1, 2)
                ))
            }
        }

        // Exactly one call: the known type only.
        assertEquals(1, rec.prlimitCalls().size)
        assertEquals(PrlimitCall(7777, Constants.RLIMIT_NOFILE, 100L, 200L),
            rec.prlimitCalls()[0])
    }

    @Test
    fun prlimitFailureWarnsButContinuesIteration() {
        // First prlimit64 fails, second one should still be attempted.
        // Use a sequence-aware stub: first call -> -1, second call -> 0.
        val callIdx = intArrayOf(0)
        val rec = RecordingSyscalls()
            .stubPrlimitReturn(0)   // will be overridden below
            .stubErrno(1 /*EPERM*/)
        // Re-stub with a sequence supplier (last writer wins for stub knobs).
        val seq = intArrayOf(-1, 0)
        rec.stubPrlimitReturn(IntSupplier { seq[callIdx[0]++] })

        SyscallHost.install(rec).use {
            Rlimit.apply(1234, listOf(
                r("RLIMIT_NOFILE", 1, 1),
                r("RLIMIT_AS", 2, 2)
            ))
        }

        assertEquals(2, rec.prlimitCalls().size,
            "second prlimit must be attempted even though first failed")
        assertEquals(PrlimitCall(1234, Constants.RLIMIT_NOFILE, 1L, 1L),
            rec.prlimitCalls()[0])
        assertEquals(PrlimitCall(1234, Constants.RLIMIT_AS, 2L, 2L),
            rec.prlimitCalls()[1])
    }
}
