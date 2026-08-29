package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.RecordingSyscalls
import com.ternbusty.takoyaki.syscall.RecordingSyscalls.KillCall
import com.ternbusty.takoyaki.syscall.SyscallHost
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.spyk
import io.mockk.unmockkObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Drives the full [KillCommand.run] method with [State.load]
 * mocked and kill(2) routed through the Syscalls trait fake. We exercise the
 * actual control flow (state load -> status check -> pid presence -> signal
 * parse -> kill -> ESRCH tolerance) without touching the real OS.
 */
class KillCommandCallTest {

    companion object {
        private const val ROOT = "/run/takoyaki"
    }

    /** Build a State with the given status+pid without touching disk. */
    private fun runningState(pid: Int): State {
        val s = State()
        s.id = "id"
        s.status = ContainerStatus.RUNNING.value
        s.pid = pid
        s.bundle = "/bundle"
        return s
    }

    @Test
    fun killRunningContainerCallsKillWithRightSignal() {
        val st = spyk(runningState(4242))
        every { st.refreshStatus() } returns st

        val rec = RecordingSyscalls()
        mockkObject(State.Companion)
        try {
            SyscallHost.install(rec).use {
                every { State.load(ROOT, "ctr-a") } returns st

                val rc = KillCommand.run(ROOT, "ctr-a", "SIGTERM", false)

                assertEquals(0, rc)
                assertEquals(listOf(KillCall(4242, Constants.SIGTERM)),
                    rec.killCalls())
            }
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun killOnStoppedContainerReturnsErrorWithoutCallingKill() {
        val st = spyk(runningState(4242))
        st.status = ContainerStatus.STOPPED.value
        every { st.refreshStatus() } returns st

        val rec = RecordingSyscalls()
        mockkObject(State.Companion)
        try {
            SyscallHost.install(rec).use {
                every { State.load(any(), any()) } returns st

                val rc = KillCommand.run(ROOT, "ctr-a", "KILL", false)

                assertEquals(1, rc, "OCI spec: kill on stopped MUST error")
                assertTrue(rec.killCalls().isEmpty(),
                    "must not invoke kill(2) on stopped container")
            }
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun esrchFromKernelIsTolerated() {
        // If the process died between refreshStatus and kill(2), the kernel
        // returns ESRCH. Per runc semantics we treat that as success.
        val st = spyk(runningState(4242))
        every { st.refreshStatus() } returns st

        val rec = RecordingSyscalls()
            .stubKillReturn(-1)
            .stubErrno(Constants.ESRCH)

        mockkObject(State.Companion)
        try {
            SyscallHost.install(rec).use {
                every { State.load(any(), any()) } returns st

                val rc = KillCommand.run(ROOT, "ctr-a", "KILL", false)

                assertEquals(0, rc, "ESRCH from kill(2) must NOT propagate as a runtime error")
                assertEquals(1, rec.killCalls().size)
            }
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun nonEsrchKillFailurePropagates() {
        val st = spyk(runningState(4242))
        every { st.refreshStatus() } returns st

        val rec = RecordingSyscalls()
            .stubKillReturn(-1)
            .stubErrno(1 /* EPERM */)

        mockkObject(State.Companion)
        try {
            SyscallHost.install(rec).use {
                every { State.load(any(), any()) } returns st

                val rc = KillCommand.run(ROOT, "ctr-a", "KILL", false)

                assertEquals(1, rc, "non-ESRCH kill errors must surface as exit 1")
            }
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun invalidSignalNameReturnsErrorBeforeAnyKill() {
        val st = spyk(runningState(4242))
        every { st.refreshStatus() } returns st

        val rec = RecordingSyscalls()
        mockkObject(State.Companion)
        try {
            SyscallHost.install(rec).use {
                every { State.load(any(), any()) } returns st

                val rc = KillCommand.run(ROOT, "ctr-a", "TOTALLY_NOT_A_SIGNAL", false)

                assertEquals(1, rc)
                assertTrue(rec.killCalls().isEmpty())
            }
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun missingPidIsAnError() {
        val st = spyk(runningState(4242))
        st.pid = null
        every { st.refreshStatus() } returns st

        val rec = RecordingSyscalls()
        mockkObject(State.Companion)
        try {
            SyscallHost.install(rec).use {
                every { State.load(any(), any()) } returns st

                val rc = KillCommand.run(ROOT, "ctr-a", "KILL", false)

                assertEquals(1, rc)
                assertTrue(rec.killCalls().isEmpty())
            }
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun stateLoadFailureReturnsErrorWithoutKill() {
        val rec = RecordingSyscalls()
        mockkObject(State.Companion)
        try {
            SyscallHost.install(rec).use {
                every { State.load(any(), any()) } throws java.io.IOException("no state.json")

                val rc = KillCommand.run(ROOT, "ctr-a", "KILL", false)

                assertEquals(1, rc)
                assertTrue(rec.killCalls().isEmpty())
            }
        } finally {
            unmockkObject(State.Companion)
        }
    }
}
