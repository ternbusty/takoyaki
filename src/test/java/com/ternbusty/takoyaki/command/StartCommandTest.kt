package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.ipc.NotifySocket
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockkObject
import io.mockk.spyk
import io.mockk.unmockkObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.IOException

class StartCommandTest {

    companion object {
        private const val ROOT = "/run/takoyaki"
    }

    private fun createdState(): State = State(
        id = "ctr-a",
        status = ContainerStatus.CREATED.value,
        pid = 4242,
        bundle = "/tmp/bundle",
    )

    @Test
    @Throws(IOException::class)
    fun startingCreatedContainerSendsNotifyAndPersistsRunning() {
        val st = spyk(createdState())
        every { st.refreshStatus() } returns st
        val updated = spyk(createdState().copy(status = ContainerStatus.RUNNING.value))
        every { updated.save(any()) } just Runs
        every { st.withStatus(ContainerStatus.RUNNING) } returns updated

        mockkObject(State.Companion, NotifySocket)
        try {
            every { State.load(any(), any()) } returns st
            every { NotifySocket.pathFor(any()) } answers { callOriginal() }
            every { NotifySocket.sendStart(any()) } just Runs

            val rc = StartCommand.run(ROOT, "ctr-a")

            assertEquals(0, rc)
            io.mockk.verify { NotifySocket.sendStart("/tmp/takoyaki-ctr-a.sock") }
            io.mockk.verify(exactly = 1) { updated.save("/run/takoyaki") }
        } finally {
            unmockkObject(State.Companion, NotifySocket)
        }
    }

    @Test
    fun startingNonCreatedContainerErrors() {
        val st = spyk(createdState().copy(status = ContainerStatus.RUNNING.value))
        every { st.refreshStatus() } returns st

        mockkObject(State.Companion, NotifySocket)
        try {
            every { State.load(any(), any()) } returns st

            val rc = StartCommand.run(ROOT, "ctr-a")

            assertEquals(1, rc, "OCI: start only valid on a 'created' container")
            io.mockk.verify(exactly = 0) { NotifySocket.sendStart(any()) }
        } finally {
            unmockkObject(State.Companion, NotifySocket)
        }
    }

    @Test
    fun stateLoadFailureReturnsError() {
        mockkObject(State.Companion)
        try {
            every { State.load(any(), any()) } throws IOException("corrupt")

            val rc = StartCommand.run(ROOT, "ctr-a")

            assertEquals(1, rc)
        } finally {
            unmockkObject(State.Companion)
        }
    }
}
