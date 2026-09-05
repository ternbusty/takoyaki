package com.ternbusty.takoyaki.contest.poststop

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * poststop hooks fire on the host AFTER the container is fully torn down
 * (delete). They're typically used to clean up state on the host that the
 * container left behind. Failure is best-effort; the delete must still
 * succeed.
 */
@Contest.RequiresTakoyaki
class PoststopTest {

    @Test
    fun poststopHookFiresAfterDelete(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val rootfs = bundle.resolve("rootfs")
        val marker = tmp.resolve("poststop-marker")
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
            "hooks" to mapOf(
                "poststop" to listOf(mapOf(
                    "path" to "/bin/sh",
                    "args" to listOf(
                        "sh", "-c",
                        "touch ${marker.toAbsolutePath()}")
                ))
            ),
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

            // Marker must NOT exist before delete.
            assertFalse(Files.exists(marker))

            // Delete the (still-created, not-started) container with --force.
            // Even without a started workload, delete still triggers poststop
            // per OCI semantics.
            Contest.run(rootDir, "delete", "--force", id)

            val deadline = System.nanoTime() + 2_000_000_000L
            while (System.nanoTime() < deadline && !Files.exists(marker)) {
                Thread.sleep(50)
            }
            assertTrue(Files.exists(marker)) {
                "poststop hook never fired (marker $marker absent)"
            }
        } finally {
            // Best-effort cleanup for the failure paths (e.g. delete itself errored).
            Contest.forceCleanup(rootDir, id)
        }
    }
}
