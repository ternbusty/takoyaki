package com.ternbusty.takoyaki.contest.hooks

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * Prestart hooks fire on the HOST (runtime namespace), after the container
 * is fully configured but before the user process is exec'd. They receive
 * the container state on stdin as JSON.
 *
 * youki's equivalent lives under tests/contest/contest/src/tests/prestart/.
 */
@Contest.RequiresTakoyaki
class HooksTest {

    @Test
    fun prestartHookRunsDuringCreate(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val marker = tmp.resolve("prestart-marker")

        // Lay down a prestart hook that touches a file on the host. We
        // never need to look inside the container — the hook ran on
        // the runtime side, so the marker shows up in the test tmpdir
        // regardless of whether the container itself has any rootfs.
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
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) {
            "create failed: ${create.stderr}"
        }

        // Hook must have fired by the time `create` returns.
        assertTrue(Files.exists(marker)) {
            "prestart hook did not run — marker file $marker" +
                " was not created. create stderr: ${create.stderr}"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }

    @Test
    fun prestartHookFailureFailsCreate(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")

        // A prestart hook returning non-zero MUST fail the create. Per OCI
        // spec, prestart hook failure aborts the lifecycle. Without that
        // gate, a container with a broken environment-prep hook would still
        // try to run the user process against an inconsistent host state.
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
                    "args" to listOf("sh", "-c", "exit 17")
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
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)

        assertNotEquals(0, create.rc,
            "create must NOT return 0 when prestart hook exits non-zero. " +
                "stdout=${create.stdout} stderr=${create.stderr}")

        // Best-effort cleanup. delete may also fail (state file may be partial).
        Contest.run(rootDir, "delete", "--force", id)
    }
}
