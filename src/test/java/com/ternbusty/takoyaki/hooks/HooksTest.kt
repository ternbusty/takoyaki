package com.ternbusty.takoyaki.hooks

import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.state.State
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class HooksTest {

    private fun sampleState(): State = State(
        id = "ctr-a",
        status = "created",
        pid = 4242,
        bundle = "/tmp/bundle",
    )

    private fun hook(path: String?, args: List<String>?, timeout: Long?): Hook =
        Hook(path = path, args = args, timeout = timeout)

    @Test
    fun nullListIsNoOp() {
        // Hooks.run must tolerate a missing hook section without throwing --
        // many specs don't define any.
        assertDoesNotThrow { Hooks.run(null, sampleState(), "prestart") }
    }

    @Test
    fun emptyListIsNoOp() {
        assertDoesNotThrow { Hooks.run(emptyList(), sampleState(), "prestart") }
    }

    @Test
    fun hookWithNullPathIsSkipped() {
        // A hook entry without a `path` is malformed but mustn't crash the
        // runtime -- silently skip and continue with the remaining hooks.
        val bad = hook(null, null, 1L)
        assertDoesNotThrow { Hooks.run(listOf(bad), sampleState(), "prestart") }
    }

    @Test
    fun hookExecutesAndReceivesStateOnStdin(@TempDir tmp: Path) {
        // End-to-end: feed the hook a real shell script that captures stdin,
        // run it, and confirm the JSON-encoded state turned up there. This is
        // the contract that runtime-tools' hooks_stdin test enforces.
        val script = tmp.resolve("hook.sh")
        val output = tmp.resolve("stdin.txt")
        Files.writeString(script, """
            #!/bin/sh
            cat > "${output}"
        """.trimIndent() + "\n")
        script.toFile().setExecutable(true)

        val h = hook(script.toString(), listOf(script.toString()), 5L)
        Hooks.run(listOf(h), sampleState(), "prestart")

        assertTrue(Files.exists(output), "hook should have written its stdin")
        val got = Files.readString(output)
        assertTrue(got.contains("\"id\""), "state JSON missing id: $got")
        assertTrue(got.contains("\"ctr-a\""), "state JSON missing id value")
        assertTrue(got.contains("\"pid\""), "state JSON missing pid field")
        assertTrue(got.contains("4242"), "state JSON missing pid value")
    }

    @Test
    fun hookExitNonZeroIsNotFatal(@TempDir tmp: Path) {
        // A failing hook is logged but mustn't crash the runtime (matches
        // runc -- only failures of "prestart" hooks block container start,
        // which the caller decides, not Hooks.run itself).
        val script = tmp.resolve("fail.sh")
        Files.writeString(script, """
            #!/bin/sh
            cat > /dev/null
            exit 7
        """.trimIndent() + "\n")
        script.toFile().setExecutable(true)

        val h = hook(script.toString(), listOf("fail.sh"), 5L)
        assertDoesNotThrow { Hooks.run(listOf(h), sampleState(), "poststart") }
    }

    @Test
    fun hookTimeoutIsHonoured(@TempDir tmp: Path) {
        // The OCI spec lets hooks specify a `timeout` in seconds. After that
        // we must SIGKILL the hook so a buggy script can't wedge container
        // lifecycle forever.
        val script = tmp.resolve("slow.sh")
        Files.writeString(script, """
            #!/bin/sh
            cat > /dev/null
            sleep 30
        """.trimIndent() + "\n")
        script.toFile().setExecutable(true)

        val h = hook(script.toString(), listOf("slow.sh"), 1L /* 1s */)
        val start = System.currentTimeMillis()
        Hooks.run(listOf(h), sampleState(), "poststop")
        val elapsed = System.currentTimeMillis() - start
        assertTrue(elapsed < 5_000,
            "timeout must have terminated the slow hook, but took ${elapsed}ms")
    }
}
