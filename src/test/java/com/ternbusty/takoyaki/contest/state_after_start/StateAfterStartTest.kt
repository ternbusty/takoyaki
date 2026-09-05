package com.ternbusty.takoyaki.contest.state_after_start

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * After start, the state JSON must reflect "running". The OCI lifecycle
 * is created -> running -> stopped, and orchestrators poll state to know
 * when start has actually taken effect.
 *
 * Needs a real user process inside the container, so this test stages
 * busybox in the rootfs and runs `sleep 60` as the workload.
 */
@Contest.RequiresTakoyaki
class StateAfterStartTest {

    @Test
    fun stateReportsRunningAfterStart(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val rootfs = bundle.resolve("rootfs")
        Files.createDirectories(rootfs)
        assumeTrue(Contest.stageBusyboxRootfs(rootfs) != null,
            "busybox not available on host; skipping start-based contest")

        // sleep 60 keeps the container alive long enough for state polling.
        // We delete-force at the end so we never wait for the actual sleep.
        Contest.writeBundle(bundle, mapOf(
            "ociVersion" to "1.0.0",
            "process" to mapOf(
                "terminal" to false,
                "args" to listOf("/bin/sleep", "60"),
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
        ))

        val id = Contest.newContainerId()
        try {
            val create = Contest.run(rootDir,
                "create", "--bundle", bundle.toString(), id)
            assertEquals(0, create.rc) { "create failed: ${create.stderr}" }

            val start = Contest.run(rootDir, "start", id)
            assertEquals(0, start.rc) { "start failed: ${start.stderr}" }

            // State takes a tick to flip from created -> running. 2-second budget
            // is generous (sleep is well-warm by 50 ms in practice).
            val reachedRunning = Contest.waitForStatus(rootDir, id, "running", 2000)
            assertTrue(reachedRunning) {
                "state never reflected 'running'. Last state: " +
                    tryReadState(rootDir, id)
            }
        } finally {
            Contest.forceCleanup(rootDir, id)
        }
    }

    private fun tryReadState(rootDir: Path, id: String): String {
        return try {
            Contest.run(rootDir, "state", id).stdout
        } catch (e: Exception) {
            "(state failed: ${e.message})"
        }
    }
}
