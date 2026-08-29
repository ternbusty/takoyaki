package com.ternbusty.takoyaki.capability

import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class CapabilityTest {

    @BeforeEach
    fun setUp() {
        mockkObject(Libc)
    }

    @AfterEach
    fun tearDown() {
        unmockkObject(Libc)
    }

    @Test
    fun idOfReturnsKnownIds() {
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
        every { Libc.prctl(any(), any(), any(), any(), any()) } returns 0
        Capability.setKeepCaps()
        verify { Libc.prctl(
            Constants.PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) }
    }

    @Test
    fun clearKeepCapsCallsPrctlZero() {
        every { Libc.prctl(any(), any(), any(), any(), any()) } returns 0
        Capability.clearKeepCaps()
        verify { Libc.prctl(
            Constants.PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) }
    }

    @Test
    fun applyBoundingSetIsNoOpForNullSpec() {
        Capability.applyBoundingSet(null)
        verify(exactly = 0) { Libc.prctl(any(), any(), any(), any(), any()) }
    }

    @Test
    fun applyBoundingSetDropsAllWhenBoundingNotSpecified() {
        every { Libc.prctl(any(), any(), any(), any(), any()) } returns 0
        val caps = Spec.LinuxCapabilities()
        Capability.applyBoundingSet(caps)
        verify { Libc.prctl(
            Constants.PR_CAPBSET_DROP, 0L, 0L, 0L, 0L) }
        verify { Libc.prctl(
            Constants.PR_CAPBSET_DROP, 1L, 0L, 0L, 0L) }
    }

    @Test
    fun applyBoundingSetDropsEverythingNotListed() {
        val caps = Spec.LinuxCapabilities()
        caps.bounding = listOf("CAP_CHOWN", "CAP_KILL") // ids 0 and 5

        every { Libc.prctl(any(), any(), any(), any(), any()) } returns 0
        Capability.applyBoundingSet(caps)

        verify(exactly = 0) { Libc.prctl(
            Constants.PR_CAPBSET_DROP, 0L, any(), any(), any()) }
        verify(exactly = 0) { Libc.prctl(
            Constants.PR_CAPBSET_DROP, 5L, any(), any(), any()) }
        verify { Libc.prctl(
            Constants.PR_CAPBSET_DROP, 1L, 0L, 0L, 0L) }
        verify { Libc.prctl(
            Constants.PR_CAPBSET_DROP, 21L, 0L, 0L, 0L) }
    }

    @Test
    fun applyBoundingSetIgnoresUnknownCapNames() {
        val caps = Spec.LinuxCapabilities()
        caps.bounding = listOf("CAP_BOGUS")

        every { Libc.prctl(any(), any(), any(), any(), any()) } returns 0
        Capability.applyBoundingSet(caps)
        verify { Libc.prctl(
            Constants.PR_CAPBSET_DROP, 0L, 0L, 0L, 0L) }
    }

    @Test
    fun applyFinalSetsCallsCapsetSyscall() {
        val caps = Spec.LinuxCapabilities()
        caps.effective = listOf("CAP_CHOWN")
        caps.permitted = listOf("CAP_CHOWN")
        caps.inheritable = emptyList()

        every { Libc.syscall(any(), any(), any(), any(), any(), any()) } returns 0L
        Capability.applyFinalSets(caps)
        verify { Libc.syscall(
            Constants.NR_capset.toLong(),
            any(), any(), 0L, 0L, 0L) }
    }

    @Test
    fun applyFinalSetsAmbientClearsThenRaisesEachListedCap() {
        val caps = Spec.LinuxCapabilities()
        caps.effective = listOf("CAP_KILL")
        caps.permitted = listOf("CAP_KILL")
        caps.inheritable = listOf("CAP_KILL")
        caps.ambient = listOf("CAP_KILL") // id 5

        every { Libc.syscall(any(), any(), any(), any(), any(), any()) } returns 0L
        every { Libc.prctl(any(), any(), any(), any(), any()) } returns 0

        Capability.applyFinalSets(caps)

        verify { Libc.prctl(
            Constants.PR_CAP_AMBIENT,
            Constants.PR_CAP_AMBIENT_CLEAR_ALL.toLong(),
            0L, 0L, 0L) }
        verify { Libc.prctl(
            Constants.PR_CAP_AMBIENT,
            Constants.PR_CAP_AMBIENT_RAISE.toLong(),
            5L, 0L, 0L) }
    }

    @Test
    fun applyFinalSetsAttemptsAmbientRaiseEvenWithoutPermittedOrInheritable() {
        val caps = Spec.LinuxCapabilities()
        caps.effective = emptyList()
        caps.permitted = emptyList()
        caps.inheritable = emptyList()
        caps.ambient = listOf("CAP_KILL")

        every { Libc.syscall(any(), any(), any(), any(), any(), any()) } returns 0L
        every { Libc.prctl(any(), any(), any(), any(), any()) } returns 0

        Capability.applyFinalSets(caps)

        verify { Libc.prctl(
            Constants.PR_CAP_AMBIENT,
            Constants.PR_CAP_AMBIENT_CLEAR_ALL.toLong(),
            0L, 0L, 0L) }
        verify { Libc.prctl(
            Constants.PR_CAP_AMBIENT,
            Constants.PR_CAP_AMBIENT_RAISE.toLong(),
            5L, 0L, 0L) }
    }

    @Test
    fun applyFinalSetsHandlesNullSpec() {
        Capability.applyFinalSets(null)
        verify(exactly = 0) { Libc.prctl(any(), any(), any(), any(), any()) }
        verify(exactly = 0) { Libc.syscall(any(), any(), any(), any(), any(), any()) }
    }
}
