package com.ternbusty.takoyaki.contest.delete_running

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * delete on a still-running container MUST fail unless --force is passed.
 * Otherwise an operator's stray `takoyaki delete id` would kill production
 * containers.
 *
 * --force MUST succeed in the same situation (the orchestrator's escape
 * hatch when it knows it wants the container gone).
 */
@Contest.RequiresTakoyaki
class DeleteRunningTest {

    @Test
    fun deleteWithoutForceOnRunningContainerErrors(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val rootfs = bundle.resolve("rootfs")
        Files.createDirectories(rootfs)
        assumeTrue(Contest.stageBusyboxRootfs(rootfs) != null,
            "busybox not available; skipping")

        Contest.writeBundle(bundle, longRunningSpec())

        val id = Contest.newContainerId()
        try {
            assertEquals(0, Contest.run(rootDir,
                "create", "--bundle", bundle.toString(), id).rc)
            assertEquals(0, Contest.run(rootDir, "start", id).rc)
            assertTrue(Contest.waitForStatus(rootDir, id, "running", 2000))

            val delete = Contest.run(rootDir, "delete", id)
            assertNotEquals(0, delete.rc) {
                "delete WITHOUT --force on a running container must fail. " +
                    "stderr=<${delete.stderr}>"
            }

            // Within-test cleanup. We still wrap with forceCleanup in finally
            // for the paths where this delete --force itself fails.
            val forced = Contest.run(rootDir, "delete", "--force", id)
            assertEquals(0, forced.rc) {
                "delete --force must succeed on running container. " +
                    "stderr=<${forced.stderr}>"
            }
        } finally {
            Contest.forceCleanup(rootDir, id)
        }
    }

    companion object {
        private fun longRunningSpec(): Map<String, Any> = mapOf(
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
        )
    }
}
