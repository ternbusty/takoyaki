package com.ternbusty.takoyaki.contest.prestart_fail

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Prestart hook with a tight timeout. The hook sleeps longer than its
 * declared timeout — the runtime MUST kill the hook, treat it as failed,
 * and abort create. A bug where timeout is ignored would let the create
 * proceed silently after killing the hook, which is non-conformant.
 */
@Contest.RequiresTakoyaki
class PrestartFailTimeoutTest {

    @Test
    fun prestartHookTimeoutAbortsCreate(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")

        Contest.writeBundle(bundle, mapOf(
            "ociVersion" to "1.0.0",
            "process" to mapOf(
                "terminal" to false,
                "args" to listOf("/bin/true"),
                "cwd" to "/",
                "user" to mapOf("uid" to 0, "gid" to 0)
            ),
            "root" to mapOf("path" to "rootfs"),
            "hooks" to mapOf(
                "prestart" to listOf(mapOf(
                    "path" to "/bin/sh",
                    "args" to listOf("sh", "-c", "sleep 10"),
                    // Timeout of 1 second; the hook sleeps 10. Kernel SIGKILL
                    // arrives at the 1-second mark and the hook becomes "failed".
                    "timeout" to 1
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
        val start = System.nanoTime()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        val elapsedMs = (System.nanoTime() - start) / 1_000_000

        assertNotEquals(0, create.rc) {
            "create with prestart timeout MUST fail. " +
                "stderr=<${create.stderr}>"
        }

        // Sanity: the whole create finished well before the hook's 10-second
        // sleep would have naturally ended. Confirms the timeout kicked in
        // rather than the hook running to completion.
        assertTrue(elapsedMs < 8000) {
            "create took $elapsedMs ms — timeout doesn't seem" +
                " to have killed the hook early"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }
}
