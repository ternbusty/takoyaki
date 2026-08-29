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

    private fun hook(path: String, args: List<String>?, timeout: Int?): Hook =
        Hook(path = path, args = args, timeout = timeout)

    @Test
    fun nullListIsNoOp() {
        assertDoesNotThrow { Hooks.run(null, sampleState(), "prestart") }
    }

    @Test
    fun emptyListIsNoOp() {
        assertDoesNotThrow { Hooks.run(emptyList(), sampleState(), "prestart") }
    }

    @Test
    fun hookExecutesAndReceivesStateOnStdin(@TempDir tmp: Path) {
        val script = tmp.resolve("hook.sh")
        val output = tmp.resolve("stdin.txt")
        Files.writeString(script, """
            #!/bin/sh
            cat > "${output}"
        """.trimIndent() + "\n")
        script.toFile().setExecutable(true)

        val h = hook(script.toString(), listOf(script.toString()), 5)
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
        val script = tmp.resolve("fail.sh")
        Files.writeString(script, """
            #!/bin/sh
            cat > /dev/null
            exit 7
        """.trimIndent() + "\n")
        script.toFile().setExecutable(true)

        val h = hook(script.toString(), listOf("fail.sh"), 5)
        assertDoesNotThrow { Hooks.run(listOf(h), sampleState(), "poststart") }
    }

    @Test
    fun hookTimeoutIsHonoured(@TempDir tmp: Path) {
        val script = tmp.resolve("slow.sh")
        Files.writeString(script, """
            #!/bin/sh
            cat > /dev/null
            sleep 30
        """.trimIndent() + "\n")
        script.toFile().setExecutable(true)

        val h = hook(script.toString(), listOf("slow.sh"), 1)
        val start = System.currentTimeMillis()
        Hooks.run(listOf(h), sampleState(), "poststop")
        val elapsed = System.currentTimeMillis() - start
        assertTrue(elapsed < 5_000,
            "timeout must have terminated the slow hook, but took ${elapsed}ms")
    }
}
