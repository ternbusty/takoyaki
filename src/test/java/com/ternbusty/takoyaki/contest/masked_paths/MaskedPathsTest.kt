package com.ternbusty.takoyaki.contest.masked_paths

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * linux.maskedPaths makes the runtime bind-mount /dev/null over each listed
 * file (or a tmpfs over each listed directory) so the container can't see
 * sensitive host state. This contest test only verifies that a spec with
 * maskedPaths is accepted end-to-end — actually validating that /proc/kcore
 * is empty inside the container requires a runtimetest binary baked into
 * the bundle's rootfs, which lives in the runtime-tools validation suite.
 *
 * youki's equivalent: tests/contest/contest/src/tests/linux_masked_paths/.
 */
@Contest.RequiresTakoyaki
class MaskedPathsTest {

    @Test
    fun specWithMaskedPathsIsAccepted(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")

        // Real-world masked paths from the runc default. Listing files
        // (/proc/kcore, /proc/keys) and directories (/proc/scsi) exercises
        // both code paths in Rootfs.maskPaths — file gets bound to /dev/null,
        // directory falls back to tmpfs.
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
                ),
                "maskedPaths" to listOf(
                    "/proc/kcore",
                    "/proc/keys",
                    "/proc/scsi",
                    "/proc/sysrq-trigger"
                )
            )
        ))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) {
            "create with maskedPaths failed: rc=${create.rc}" +
                " stdout=<${create.stdout}> stderr=<${create.stderr}>"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }

    @Test
    fun specWithReadonlyPathsIsAccepted(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")

        // readonlyPaths is the sibling of maskedPaths: each path gets self-bound
        // and then MS_REMOUNTed read-only. Listed as a separate test because
        // Rootfs.readonlyRemount is a different code path from maskPaths.
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
                ),
                "readonlyPaths" to listOf(
                    "/proc/asound",
                    "/proc/bus",
                    "/proc/fs",
                    "/proc/irq",
                    "/proc/sys"
                )
            )
        ))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) {
            "create with readonlyPaths failed: rc=${create.rc}" +
                " stderr=<${create.stderr}>"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }
}
