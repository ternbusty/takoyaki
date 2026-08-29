package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.ipc.NotifySocket
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.Json
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

    private fun createdState(): State {
        val s = State()
        s.id = "ctr-a"
        s.status = ContainerStatus.CREATED.value
        s.pid = 4242
        s.bundle = "/tmp/bundle"
        return s
    }

    @Test
    @Throws(IOException::class)
    fun startingCreatedContainerSendsNotifyAndPersistsRunning() {
        val st = spyk(createdState())
        every { st.refreshStatus() } returns st
        // withStatus(RUNNING) must return a State whose save() is harmless in
        // tests — spy it.
        val updated = spyk(createdState())
        updated.status = ContainerStatus.RUNNING.value
        every { updated.save(any()) } just Runs
        every { st.withStatus(ContainerStatus.RUNNING) } returns updated

        // Build a Spec with non-empty process.args. StartCommand validates
        // that process.args isn't empty before signalling — without this,
        // start refuses with "spec.process.args is missing or empty".
        val spec = Spec()
        spec.process = Spec.Process()
        spec.process!!.args = listOf("/bin/true")

        mockkObject(State.Companion, NotifySocket, Json)
        try {
            every { State.load(any(), any()) } returns st
            every { Json.readFile(any<java.nio.file.Path>(), any<(Any?) -> Spec>()) } returns spec
            // pathFor is a pure path builder — let the real one run so the
            // sendStart verification below checks the canonical path.
            every { NotifySocket.pathFor(any()) } answers { callOriginal() }
            every { NotifySocket.sendStart(any()) } just Runs

            val rc = StartCommand.run(ROOT, "ctr-a")

            assertEquals(0, rc)
            // NotifySocket.sendStart is the actual "go" signal across the
            // unix domain socket — verify it fired with the canonical path.
            io.mockk.verify { NotifySocket.sendStart("/tmp/takoyaki-ctr-a.sock") }
            io.mockk.verify(exactly = 1) { updated.save("/run/takoyaki") }
        } finally {
            unmockkObject(State.Companion, NotifySocket, Json)
        }
    }

    @Test
    fun startingNonCreatedContainerErrors() {
        val st = spyk(createdState())
        st.status = ContainerStatus.RUNNING.value
        every { st.refreshStatus() } returns st

        mockkObject(State.Companion, NotifySocket)
        try {
            every { State.load(any(), any()) } returns st

            val rc = StartCommand.run(ROOT, "ctr-a")

            assertEquals(1, rc, "OCI: start only valid on a 'created' container")
            // No "go" signal should have been sent.
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
