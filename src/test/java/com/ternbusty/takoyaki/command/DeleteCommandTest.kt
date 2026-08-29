package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.IOException

class DeleteCommandTest {

    companion object {
        private const val ROOT = "/run/takoyaki"
    }

    private fun stoppedState(): State {
        val s = State()
        s.id = "ctr-a"
        s.status = ContainerStatus.STOPPED.value
        s.pid = 4242
        s.bundle = "/tmp/bundle"
        return s
    }

    private fun runningState(): State {
        val s = State()
        s.id = "ctr-a"
        s.status = ContainerStatus.RUNNING.value
        s.pid = 4242
        s.bundle = "/tmp/bundle"
        return s
    }

    @Test
    fun deletingMissingContainerWithoutForceErrors() {
        mockkObject(State.Companion)
        try {
            every { State.exists(any(), any()) } returns false
            val rc = DeleteCommand.run(ROOT, "missing", false)
            assertEquals(1, rc)
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun deletingMissingContainerWithForceSucceeds() {
        // --force on a non-existent container is a soft no-op so that cleanup
        // scripts that always run `delete --force` don't trip.
        mockkObject(State.Companion)
        try {
            every { State.exists(any(), any()) } returns false
            val rc = DeleteCommand.run(ROOT, "missing", true)
            assertEquals(0, rc)
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun deletingRunningContainerWithoutForceErrorsAndDoesNotKill() {
        val st = spyk(runningState())
        every { st.refreshStatus() } returns st

        mockkObject(State.Companion)
        mockkStatic(Libc::kill)
        try {
            every { State.exists(any(), any()) } returns true
            every { State.load(any(), any()) } returns st

            val rc = DeleteCommand.run(ROOT, "ctr-a", false)

            assertEquals(1, rc, "OCI: delete on non-stopped MUST error without --force")
            io.mockk.verify(exactly = 0) { Libc.kill(any(), any()) }
        } finally {
            unmockkStatic(Libc::kill)
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun deletingRunningContainerWithForceSendsSigkill() {
        val st = spyk(runningState())
        every { st.refreshStatus() } returns st

        mockkObject(State.Companion)
        mockkStatic(Libc::kill)
        try {
            every { State.exists(any(), any()) } returns true
            every { State.load(any(), any()) } returns st
            every { State.containerDir(any(), any()) } returns java.nio.file.Path.of("/tmp/nonexistent-container-dir")
            every { Libc.kill(any(), any()) } returns 0

            val rc = DeleteCommand.run(ROOT, "ctr-a", true)

            assertEquals(0, rc)
            io.mockk.verify { Libc.kill(4242, Constants.SIGKILL) }
        } finally {
            unmockkStatic(Libc::kill)
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun deletingStoppedContainerSkipsKill() {
        val st = spyk(stoppedState())
        every { st.refreshStatus() } returns st

        mockkObject(State.Companion)
        mockkStatic(Libc::kill)
        try {
            every { State.exists(any(), any()) } returns true
            every { State.load(any(), any()) } returns st
            every { State.containerDir(any(), any()) } returns java.nio.file.Path.of("/tmp/nonexistent-container-dir")

            val rc = DeleteCommand.run(ROOT, "ctr-a", false)

            assertEquals(0, rc)
            // No kill should be issued — container is already stopped.
            io.mockk.verify(exactly = 0) { Libc.kill(any(), any()) }
        } finally {
            unmockkStatic(Libc::kill)
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun stateLoadFailureReturnsError() {
        mockkObject(State.Companion)
        try {
            every { State.exists(any(), any()) } returns true
            every { State.load(any(), any()) } throws IOException("corrupt")

            val rc = DeleteCommand.run(ROOT, "ctr-a", false)

            assertEquals(1, rc)
        } finally {
            unmockkObject(State.Companion)
        }
    }
}
