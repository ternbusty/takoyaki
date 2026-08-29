package com.ternbusty.takoyaki.capability

import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.*
import org.mockito.Mockito.*
import org.junit.jupiter.api.Assertions.*

class CapabilityTest {

    @Test
    fun idOfReturnsKnownIds() {
        // OCI capabilities are spelled as CAP_*. We must agree with the kernel
        // numbering so capset / PR_CAPBSET_DROP / PR_CAP_AMBIENT_RAISE target
        // the right bit. Pin a few well-known ones.
        assertEquals(0, Capability.idOf("CAP_CHOWN"))
        assertEquals(1, Capability.idOf("CAP_DAC_OVERRIDE"))
        assertEquals(5, Capability.idOf("CAP_KILL"))
        assertEquals(21, Capability.idOf("CAP_SYS_ADMIN"))
        assertEquals(-1, Capability.idOf("CAP_BOGUS"),
            "unknown cap name returns -1 (sentinel checked by callers)")
        assertEquals(-1, Capability.idOf(null))
    }

    @Test
    fun setKeepCapsCallsPrctlOne() {
        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()) }
                .thenReturn(0)
            Capability.setKeepCaps()
            lm.verify { Libc.prctl(
                eq(Constants.PR_SET_KEEPCAPS), eq(1L), eq(0L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun clearKeepCapsCallsPrctlZero() {
        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()) }
                .thenReturn(0)
            Capability.clearKeepCaps()
            lm.verify { Libc.prctl(
                eq(Constants.PR_SET_KEEPCAPS), eq(0L), eq(0L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun applyBoundingSetIsNoOpForNullSpec() {
        mockStatic(Libc::class.java).use { lm ->
            Capability.applyBoundingSet(null)
            lm.verifyNoInteractions()
        }
    }

    @Test
    fun applyBoundingSetDropsAllWhenBoundingNotSpecified() {
        // When caps is non-null but bounding is null, runc treats it as an
        // empty keep set and drops every capability from the bounding set.
        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()) }
                .thenReturn(0)
            val caps = Spec.LinuxCapabilities()
            Capability.applyBoundingSet(caps)
            // CAP_CHOWN (0), CAP_DAC_OVERRIDE (1), etc. must all be dropped.
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAPBSET_DROP), eq(0L), eq(0L), eq(0L), eq(0L)) }
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAPBSET_DROP), eq(1L), eq(0L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun applyBoundingSetDropsEverythingNotListed() {
        // The bounding set contract: ANY cap not in spec.bounding must be
        // PR_CAPBSET_DROP'd. Verify we drop the ones outside the list AND
        // never drop the ones we kept.
        val caps = Spec.LinuxCapabilities()
        caps.bounding = listOf("CAP_CHOWN", "CAP_KILL") // ids 0 and 5

        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()) }
                .thenReturn(0)
            Capability.applyBoundingSet(caps)

            // 0 (CHOWN) and 5 (KILL) must NOT be dropped.
            lm.verify({ Libc.prctl(
                eq(Constants.PR_CAPBSET_DROP), eq(0L), anyLong(), anyLong(), anyLong()) },
                never())
            lm.verify({ Libc.prctl(
                eq(Constants.PR_CAPBSET_DROP), eq(5L), anyLong(), anyLong(), anyLong()) },
                never())
            // 1 (DAC_OVERRIDE) and 21 (SYS_ADMIN) must be dropped.
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAPBSET_DROP), eq(1L), eq(0L), eq(0L), eq(0L)) }
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAPBSET_DROP), eq(21L), eq(0L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun applyBoundingSetIgnoresUnknownCapNames() {
        // An unknown cap name in spec must NOT poison the loop or accidentally
        // KEEP every cap (id=-1 → not in keep set → everything dropped, which
        // is the safe failure mode we want).
        val caps = Spec.LinuxCapabilities()
        caps.bounding = listOf("CAP_BOGUS")

        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()) }
                .thenReturn(0)
            Capability.applyBoundingSet(caps)
            // CAP_CHOWN (id 0) must be dropped because the bogus name didn't
            // make it into the keep set.
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAPBSET_DROP), eq(0L), eq(0L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun applyFinalSetsCallsCapsetSyscall() {
        // applyFinalSets builds eff/per/inh bit masks and hands them to
        // syscall(NR_capset, ...). Validate the call happens for a non-empty
        // spec.
        val caps = Spec.LinuxCapabilities()
        caps.effective = listOf("CAP_CHOWN")
        caps.permitted = listOf("CAP_CHOWN")
        caps.inheritable = emptyList()

        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.syscall(anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong()) }.thenReturn(0L)
            Capability.applyFinalSets(caps)
            lm.verify { Libc.syscall(
                eq(Constants.NR_capset.toLong()),
                anyLong(), anyLong(), eq(0L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun applyFinalSetsAmbientClearsThenRaisesEachListedCap() {
        // The kernel requires an ambient cap to also be in both permitted
        // AND inheritable. Reflect a valid spec so the pre-check in
        // applyFinalSets actually lets the RAISE call through.
        val caps = Spec.LinuxCapabilities()
        caps.effective = listOf("CAP_KILL")
        caps.permitted = listOf("CAP_KILL")
        caps.inheritable = listOf("CAP_KILL")
        caps.ambient = listOf("CAP_KILL") // id 5

        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.syscall(anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong()) }.thenReturn(0L)
            lm.`when`<Any> { Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()) }
                .thenReturn(0)

            Capability.applyFinalSets(caps)

            // First clear ALL ambient caps.
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAP_AMBIENT),
                eq(Constants.PR_CAP_AMBIENT_CLEAR_ALL.toLong()),
                eq(0L), eq(0L), eq(0L)) }
            // Then raise the requested ones (CAP_KILL = 5).
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAP_AMBIENT),
                eq(Constants.PR_CAP_AMBIENT_RAISE.toLong()),
                eq(5L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun applyFinalSetsAttemptsAmbientRaiseEvenWithoutPermittedOrInheritable() {
        // Spec asks for ambient=[CAP_KILL] but doesn't put CAP_KILL in
        // permitted+inheritable. Runc always attempts the RAISE and prints
        // a warning on failure rather than skipping the call.
        val caps = Spec.LinuxCapabilities()
        caps.effective = emptyList()
        caps.permitted = emptyList()
        caps.inheritable = emptyList()
        caps.ambient = listOf("CAP_KILL")

        mockStatic(Libc::class.java).use { lm ->
            lm.`when`<Any> { Libc.syscall(anyLong(), anyLong(), anyLong(),
                anyLong(), anyLong(), anyLong()) }.thenReturn(0L)
            lm.`when`<Any> { Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()) }
                .thenReturn(0)

            Capability.applyFinalSets(caps)

            lm.verify { Libc.prctl(
                eq(Constants.PR_CAP_AMBIENT),
                eq(Constants.PR_CAP_AMBIENT_CLEAR_ALL.toLong()),
                eq(0L), eq(0L), eq(0L)) }
            // RAISE is always attempted (runc compat). On a real kernel the
            // call would fail with EPERM and a warning is printed to stderr.
            lm.verify { Libc.prctl(
                eq(Constants.PR_CAP_AMBIENT),
                eq(Constants.PR_CAP_AMBIENT_RAISE.toLong()),
                eq(5L), eq(0L), eq(0L)) }
        }
    }

    @Test
    fun applyFinalSetsHandlesNullSpec() {
        mockStatic(Libc::class.java).use { lm ->
            Capability.applyFinalSets(null)
            lm.verifyNoInteractions()
        }
    }
}
