package com.ternbusty.takoyaki.contest.exeseal

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Verify CVE-2019-5736 mitigation: ExeSeal.cloneSelfExe must succeed during
 * container creation. If it fails, CreateCommand returns non-zero with a
 * "CVE-2019-5736" error message.
 *
 * This is an end-to-end gate: if create succeeds, the sealed fd was
 * successfully produced (overlayfs or memfd) and the child was exec'd through
 * /proc/self/fd/N rather than the on-disk binary.
 */
@Contest.RequiresTakoyaki
class ExeSealTest {

    @Test
    fun createSucceedsWithExeSeal(@TempDir tmp: Path) {
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

        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) {
            "create with exe-seal failed: ${create.stderr}"
        }
        assertFalse(create.stderr.contains("CVE-2019-5736"),
            "exe-seal should not report failure")

        try {
            val state = Contest.run(rootDir, "state", id)
            assertTrue(state.stdout.contains("\"status\"")) {
                "state should return valid JSON: ${state.stdout}"
            }
        } finally {
            Contest.forceCleanup(rootDir, id)
        }
    }
}
