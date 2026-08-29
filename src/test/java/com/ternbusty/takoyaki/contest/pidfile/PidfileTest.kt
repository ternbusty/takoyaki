package com.ternbusty.takoyaki.contest.pidfile

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * --pid-file is how runc / containerd-shim hands the container init pid back
 * to the orchestrator. Without a correctly-written pidfile, ctr / kubelet
 * can't kill or attach to the container.
 */
@Contest.RequiresTakoyaki
class PidfileTest {

    @Test
    fun pidFileIsCreatedWithPositiveInteger(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val pidFile = tmp.resolve("pid")

        Contest.writeBundle(bundle, baseSpec())

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(),
            "--pid-file", pidFile.toString(), id)
        assertEquals(0, create.rc) { "create failed: ${create.stderr}" }

        assertTrue(Files.exists(pidFile)) {
            "pid file $pidFile was not written by create"
        }

        val content = Files.readString(pidFile).trim()
        val pid = content.toInt()
        assertTrue(pid > 0) {
            "pid file must contain a positive integer, got: <$content>"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }

    @Test
    fun absentPidFileFlagWritesNoFile(@TempDir tmp: Path) {
        // Without --pid-file, no file should be created at the default location.
        // The orchestrator opts in to pid-file plumbing per call.
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")

        Contest.writeBundle(bundle, baseSpec())

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc)

        // Nothing in the parent tempdir should have showed up as a pid file.
        // We only check that no "pid" file appeared next to the bundle.
        assertFalse(Files.exists(bundle.parent.resolve("pid")))

        Contest.run(rootDir, "delete", "--force", id)
    }

    companion object {
        private fun baseSpec(): Map<String, Any> = mapOf(
            "ociVersion" to "1.0.0",
            "process" to mapOf(
                "terminal" to false,
                "args" to listOf("/bin/true"),
                "cwd" to "/",
                "user" to mapOf("uid" to 0, "gid" to 0)
            ),
            "root" to mapOf("path" to "rootfs"),
            "linux" to mapOf(
                "namespaces" to listOf(
                    mapOf("type" to "pid"),
                    mapOf("type" to "mount"),
                    mapOf("type" to "ipc"),
                    mapOf("type" to "uts"),
                    mapOf("type" to "cgroup")
                )
            )
        )
    }
}
