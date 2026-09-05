package com.ternbusty.takoyaki.contest.duplicate_id

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Container ids are unique per --root directory. Creating the same id twice
 * MUST fail; otherwise orchestrators that hold an id-keyed map would lose
 * track of the original container and orphan it.
 */
@Contest.RequiresTakoyaki
class DuplicateIdTest {

    @Test
    fun secondCreateWithSameIdFails(@TempDir tmp: Path) {
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

        val first = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, first.rc) { "first create failed: ${first.stderr}" }

        // Second create with the same id MUST fail. Tolerating it would
        // overwrite the existing state.json and lose the pid.
        val second = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertNotEquals(0, second.rc) {
            "second create with the same id MUST fail. " +
                "stdout=<${second.stdout}> stderr=<${second.stderr}>"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }
}
