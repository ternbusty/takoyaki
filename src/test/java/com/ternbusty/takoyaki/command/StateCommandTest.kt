package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.spyk
import io.mockk.unmockkObject
import io.mockk.verify
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.PrintStream

class StateCommandTest {

    companion object {
        private const val ROOT = "/run/takoyaki"
    }

    private val realStdout: PrintStream = System.out
    private lateinit var capturedStdout: ByteArrayOutputStream

    @BeforeEach
    fun captureStdout() {
        capturedStdout = ByteArrayOutputStream()
        System.setOut(PrintStream(capturedStdout))
    }

    @AfterEach
    fun restoreStdout() {
        System.setOut(realStdout)
    }

    private fun sampleState(): State = State(
        ociVersion = "1.0.0",
        id = "ctr-a",
        status = ContainerStatus.RUNNING.value,
        pid = 4242,
        bundle = "/tmp/bundle",
    )

    @Test
    fun printsStateJsonOnSuccess() {
        val st = spyk(sampleState())
        every { st.refreshStatus() } returns st

        mockkObject(State.Companion)
        try {
            every { State.load("/run/takoyaki", "ctr-a") } returns st

            val rc = StateCommand.run(ROOT, "ctr-a")

            assertEquals(0, rc)
            val out = capturedStdout.toString()
            assertTrue(out.contains("\"id\""), "output missing id field: $out")
            assertTrue(out.contains("\"ctr-a\""), "output missing id value: $out")
            assertTrue(out.contains("\"running\""), "status must be lowercase 'running'")
            assertTrue(out.contains("\"pid\""), "output missing pid field")
            assertTrue(out.contains("4242"), "output missing pid value")
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun returnsNonzeroOnStateLoadFailure() {
        mockkObject(State.Companion)
        try {
            every { State.load(any(), any()) } throws IOException("no such container")

            val rc = StateCommand.run(ROOT, "missing")

            assertEquals(1, rc)
            assertEquals("", capturedStdout.toString(),
                "no JSON should be printed on failure (stderr-only error log)")
        } finally {
            unmockkObject(State.Companion)
        }
    }

    @Test
    fun refreshStatusIsCalled() {
        val st = spyk(sampleState())
        every { st.refreshStatus() } returns st

        mockkObject(State.Companion)
        try {
            every { State.load(any(), any()) } returns st
            StateCommand.run(ROOT, "ctr-a")
            verify(exactly = 1) { st.refreshStatus() }
        } finally {
            unmockkObject(State.Companion)
        }
    }
}
