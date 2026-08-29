package com.ternbusty.takoyaki.config

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.IOException
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.*

class KontainerConfigTest {

    @Test
    fun pathIsRootSlashIdSlashConfigJson() {
        // pause/resume/freeze all hang off this exact filename. If the convention
        // drifts, every subcommand stops finding the cgroup.
        val p = KontainerConfig.path("/run/takoyaki", "abc")
        assertEquals(Path.of("/run/takoyaki/abc/config.json"), p)
    }

    @Test
    fun saveAndLoadRoundTripsCgroupPath(@TempDir tmp: Path) {
        val c = KontainerConfig("/sys/fs/cgroup/user.slice/x")
        c.save(tmp.toString(), "ctr-1")

        val loaded = KontainerConfig.load(tmp.toString(), "ctr-1")
        assertEquals("/sys/fs/cgroup/user.slice/x", loaded.cgroupPath)
    }

    @Test
    fun saveCreatesContainerDirectoryIfMissing(@TempDir tmp: Path) {
        // Crucially this must NOT require the caller to mkdir first — Create
        // saves config.json as part of the same call sequence.
        val c = KontainerConfig("/sys/fs/cgroup/x")
        c.save(tmp.toString(), "freshly-created")
        assertTrue(java.nio.file.Files.exists(
            tmp.resolve("freshly-created").resolve("config.json")))
    }

    @Test
    fun loadMissingFileThrowsIoException(@TempDir tmp: Path) {
        // Subcommands like pause distinguish "no config" from "wrong cgroup"
        // via the IOException. Don't let it be silently swallowed.
        assertThrows(IOException::class.java) {
            KontainerConfig.load(tmp.toString(), "never-existed")
        }
    }

    @Test
    fun nullCgroupPathIsAllowedAndRoundTrips(@TempDir tmp: Path) {
        // Containers without resources.cgroupsPath leave this null. We must
        // serialize it as null rather than blowing up on JsonCodec.encode.
        val c = KontainerConfig(null)
        c.save(tmp.toString(), "no-cgroup")
        val loaded = KontainerConfig.load(tmp.toString(), "no-cgroup")
        assertNull(loaded.cgroupPath)
    }
}
