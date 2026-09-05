package com.ternbusty.takoyaki.state

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.IOException
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.*

class StateRoundTripTest {

    @Test
    fun saveAndLoadPreservesAllFields(@TempDir tmp: Path) {
        // Saving then loading must round-trip every field that runtime-tools
        // and downstream hooks rely on. If a field is silently dropped at the
        // JSON layer, killsig/hooks_stdin/pidfile etc. all start misbehaving.
        val s = State.create(
            "1.0.0", "ctr-42", ContainerStatus.CREATED,
            12345, "/tmp/bundle",
            mapOf("org.example/k" to "v")
        )
        s.save(tmp.toString())

        val loaded = State.load(tmp.toString(), "ctr-42")

        assertEquals("1.0.0", loaded.ociVersion)
        assertEquals("ctr-42", loaded.id)
        assertEquals("created", loaded.status)
        assertEquals(12345, loaded.pid)
        assertEquals("/tmp/bundle", loaded.bundle)
        assertEquals(mapOf("org.example/k" to "v"), loaded.annotations)
        assertNotNull(loaded.created, "created timestamp must be preserved")
    }

    @Test
    fun existsReportsContainerLifecycle(@TempDir tmp: Path) {
        // exists() is the cheap guard that prevents create from racing against
        // itself and delete from acting on a non-container.
        assertFalse(
            State.exists(tmp.toString(), "absent"),
            "exists() returns false before any save"
        )
        val s = State.create("1.0.0", "abc", ContainerStatus.CREATED, 1, "/b", null)
        s.save(tmp.toString())
        assertTrue(
            State.exists(tmp.toString(), "abc"),
            "exists() returns true after save"
        )
    }

    @Test
    fun containerDirPathIsRootPathSlashId() {
        val p = State.containerDir("/run/takoyaki", "abc")
        assertEquals(Path.of("/run/takoyaki/abc"), p)
    }

    @Test
    fun statePathIsContainerDirSlashStateJson() {
        val p = State.statePath("/run/takoyaki", "abc")
        assertEquals(Path.of("/run/takoyaki/abc/state.json"), p)
    }

    @Test
    fun withStatusReturnsACopyWithJustTheStatusChanged() {
        val original = State.create(
            "1.0.0", "x", ContainerStatus.CREATED,
            10, "/b", null
        )
        val running = original.withStatus(ContainerStatus.RUNNING)

        // Original is untouched.
        assertEquals("created", original.status)
        // Running has new status but every other field the same.
        assertEquals("running", running.status)
        assertEquals(original.id, running.id)
        assertEquals(original.pid, running.pid)
        assertEquals(original.bundle, running.bundle)
        assertEquals(original.ociVersion, running.ociVersion)
    }
}
