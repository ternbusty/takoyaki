package com.ternbusty.takoyaki.contest.invalid_spec

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * Malformed config.json must produce a clean non-zero exit, never a hang
 * and never a stack trace dump that the operator has to read 30 lines of.
 *
 * youki's analogue lives at tests/contest/contest/src/tests/misc_props/.
 */
@Contest.RequiresTakoyaki
class InvalidSpecTest {

    @Test
    fun completelyMalformedJsonFailsCleanly(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        Files.createDirectories(bundle)
        Files.createDirectories(bundle.resolve("rootfs"))
        Files.writeString(bundle.resolve("config.json"), "{this is not valid json")

        val r = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(),
            Contest.newContainerId())

        assertNotEquals(0, r.rc) {
            "malformed config.json must NOT silently succeed. " +
                "stdout=<${r.stdout}> stderr=<${r.stderr}>"
        }
    }

    @Test
    fun missingConfigJsonFailsCleanly(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        Files.createDirectories(bundle)
        Files.createDirectories(bundle.resolve("rootfs"))
        // no config.json

        val r = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(),
            Contest.newContainerId())

        assertNotEquals(0, r.rc) { "missing config.json must error. stderr=<${r.stderr}>" }
    }

    @Test
    fun emptyArgsListLetsCreateAndStartProceed(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        // process.args=[] is malformed per spec, but runtime-tools
        // validation/start expects the runtime to accept it through create
        // AND start (the buggy `err == nil` assertion in runtime-tools
        // upstream's start test 7). The container then reaches 'stopped'
        // naturally because InitProcess detects empty args and _exits(1).
        // We pin "create exits 0 and start exits 0" so we notice if we ever
        // accidentally start rejecting at the wrong phase again.
        Contest.writeBundle(bundle, mapOf(
            "ociVersion" to "1.0.0",
            "process" to mapOf(
                "terminal" to false,
                "args" to emptyList<String>(),
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
            assertEquals(0, create.rc) {
                "create with empty args must succeed. stderr=<${create.stderr}>"
            }

            val start = Contest.run(rootDir, "start", id)
            assertEquals(0, start.rc) {
                "start with empty args must succeed (init handles the exit). " +
                    "stderr=<${start.stderr}>"
            }
        } finally {
            Contest.run(rootDir, "delete", "--force", id)
        }
    }
}
