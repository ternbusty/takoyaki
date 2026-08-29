package com.ternbusty.takoyaki.contest.poststart

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * poststart hooks fire on the host after the user process is exec'd. Unlike
 * prestart, a failure is logged but does NOT abort the lifecycle.
 */
@Contest.RequiresTakoyaki
class PoststartTest {

    @Test
    fun poststartHookFiresAfterStart(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val rootfs = bundle.resolve("rootfs")
        val marker = tmp.resolve("poststart-marker")
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
                "poststart" to listOf(mapOf(
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

            // Marker must NOT exist before start — poststart is start-time, not create-time.
            assertFalse(Files.exists(marker)) {
                "poststart fired during create — wrong phase. marker=$marker"
            }

            val start = Contest.run(rootDir, "start", id)
            assertEquals(0, start.rc) { "start failed: ${start.stderr}" }

            // Give the hook a moment to run; we don't wait on start's process
            // synchronously for hooks.
            val deadline = System.nanoTime() + 2_000_000_000L
            while (System.nanoTime() < deadline && !Files.exists(marker)) {
                Thread.sleep(50)
            }
            assertTrue(Files.exists(marker)) {
                "poststart hook never fired (marker $marker absent). " +
                    "start stderr: ${start.stderr}"
            }
        } finally {
            Contest.forceCleanup(rootDir, id)
        }
    }
}
