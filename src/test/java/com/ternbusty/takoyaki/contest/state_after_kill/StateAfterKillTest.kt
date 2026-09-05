package com.ternbusty.takoyaki.contest.state_after_kill

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * After kill SIGKILL, the state JSON must reflect "stopped". Orchestrators
 * use this transition to know it's safe to call delete.
 */
@Contest.RequiresTakoyaki
class StateAfterKillTest {

    @Test
    fun killSigkillTransitionsToStopped(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val rootfs = bundle.resolve("rootfs")
        Files.createDirectories(rootfs)
        assumeTrue(Contest.stageBusyboxRootfs(rootfs) != null,
            "busybox not available; skipping")

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
            assertEquals(0, Contest.run(rootDir,
                "create", "--bundle", bundle.toString(), id).rc)
            assertEquals(0, Contest.run(rootDir, "start", id).rc)
            assertTrue(Contest.waitForStatus(rootDir, id, "running", 2000),
                "container never reached running")

            val kill = Contest.run(rootDir, "kill", id, "KILL")
            assertEquals(0, kill.rc) { "kill failed: ${kill.stderr}" }

            // SIGKILL is immediate, but state refresh involves a kill(pid, 0)
            // probe — give it 2 seconds to settle.
            val stopped = Contest.waitForStatus(rootDir, id, "stopped", 2000)
            assertTrue(stopped) {
                "state never reached 'stopped' after SIGKILL. Last state: " +
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
