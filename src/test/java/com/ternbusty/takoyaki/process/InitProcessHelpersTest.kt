package com.ternbusty.takoyaki.process

import org.junit.jupiter.api.Test
import java.util.Base64
import org.junit.jupiter.api.Assertions.*

/**
 * Pure helpers extracted from InitProcess.run.
 *
 * The `_TAKOYAKI_IDMAP_FDS` env value is consumed by Stage-2 (PID 1
 * inside the container's pid namespace) to look up host-prepared user-ns
 * fds for idmap-mount(). A bug here can silently fall back to in-init helper
 * forking, which deadlocks because /proc shows host pids inside the pid ns.
 */
class InitProcessHelpersTest {

    private fun enc(s: String): String =
        Base64.getEncoder().encodeToString(s.toByteArray())

    @Test
    fun nullEnvProducesEmptyMap() {
        // Most containers have no idmap mounts; null env must be a clean no-op.
        assertTrue(InitProcess.parseIdmapFds(null).isEmpty())
    }

    @Test
    fun emptyEnvProducesEmptyMap() {
        assertTrue(InitProcess.parseIdmapFds("").isEmpty())
    }

    @Test
    fun singleEntryRoundTripsBase64AndFd() {
        val env = "${enc("/data")}:7"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(1, got.size)
        assertEquals(7, got["/data"])
    }

    @Test
    fun multipleEntriesAreCommaSeparated() {
        // Three entries, each base64(dest):fd, joined with comma.
        val env = "${enc("/a")}:3,${enc("/b")}:5,${enc("/c")}:11"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(3, got.size)
        assertEquals(3, got["/a"])
        assertEquals(5, got["/b"])
        assertEquals(11, got["/c"])
    }

    @Test
    fun destPathWithCommaIsHandledByBase64() {
        // The whole point of base64-encoding the destination is that paths
        // containing '=' or ',' don't break the outer split. Make sure that
        // actually works.
        val weirdPath = "/mnt/dir,with,commas"
        val env = "${enc(weirdPath)}:99"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(99, got[weirdPath])
    }

    @Test
    fun entryWithoutColonIsSkipped() {
        // A malformed entry must NOT abort the whole parse — we still want the
        // other entries through. Better to lose one idmap mount than fail init.
        val env = "this-has-no-colon,${enc("/good")}:42"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(1, got.size)
        assertEquals(42, got["/good"])
    }

    @Test
    fun entryWithBadBase64IsSkippedAndOthersStillParse() {
        // base64 decoder throws IllegalArgumentException on garbage; we swallow.
        val env = "!!!not-base64!!!:7,${enc("/good")}:3"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(1, got.size)
        assertEquals(3, got["/good"])
    }

    @Test
    fun entryWithNonNumericFdIsSkipped() {
        // fd must parse as int; otherwise we'd later pass garbage to a syscall.
        val env = "${enc("/good")}:NaN,${enc("/keep")}:4"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(1, got.size)
        assertEquals(4, got["/keep"])
    }

    @Test
    fun duplicateDestinationLastEntryWins() {
        // Last-writer-wins is the simple, predictable rule. Documenting it.
        val env = "${enc("/same")}:1,${enc("/same")}:2"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(2, got["/same"])
    }

    @Test
    fun insertionOrderPreserved() {
        // Stage-2 doesn't rely on order today, but a LinkedHashMap keeps the
        // door open for ordered application (e.g. parent-before-child mounts).
        val env = "${enc("/c")}:1,${enc("/a")}:2,${enc("/b")}:3"
        val got = InitProcess.parseIdmapFds(env)
        assertEquals(listOf("/c", "/a", "/b"), got.keys.toList())
    }
}
