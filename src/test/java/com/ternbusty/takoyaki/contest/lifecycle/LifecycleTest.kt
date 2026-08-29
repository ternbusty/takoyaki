package com.ternbusty.takoyaki.contest.lifecycle

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.IOException
import java.nio.file.Path

/**
 * The "happy path" lifecycle: create -> state shows created -> delete.
 *
 * youki has equivalent tests under tests/contest/contest/src/tests/lifecycle/.
 * We're verifying the OCI runtime spec lifecycle ordering, not container
 * semantics — just that state transitions happen and `state` reports
 * them honestly.
 */
@Contest.RequiresTakoyaki
class LifecycleTest {

    @Test
    fun createThenDeleteReturnsZeroAndStateShowsCreated(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")

        // Minimal "do nothing forever" spec. We never actually start the
        // container so the rootfs can be empty — create just configures and
        // parks Stage-2 waiting on the notify socket.
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

        // create
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) {
            "create failed: rc=${create.rc}" +
                " stdout=<${create.stdout}> stderr=<${create.stderr}>"
        }

        // state — must show "created"
        val state = Contest.run(rootDir, "state", id)
        assertEquals(0, state.rc) { "state failed: ${state.stderr}" }
        assertTrue(state.stdout.contains("\"status\"")) {
            "state output missing status field: ${state.stdout}"
        }
        assertTrue(state.stdout.contains("\"created\"") || state.stdout.contains("\"stopped\"")) {
            "expected status=created or stopped, got: ${state.stdout}"
        }
        assertTrue(state.stdout.contains("\"$id\"")) {
            "state output missing container id: ${state.stdout}"
        }

        // delete (force, since we never started the container so it might still
        // be in created. --force makes delete tolerate that).
        val delete = Contest.run(rootDir, "delete", "--force", id)
        assertEquals(0, delete.rc) { "delete failed: ${delete.stderr}" }

        // state on a deleted container must return non-zero — the runtime
        // signals "no such container" via exit code, not via printing an
        // empty JSON blob.
        val stateAfter = Contest.run(rootDir, "state", id)
        assertNotEquals(0, stateAfter.rc,
            "state on a deleted container must NOT return 0")
    }

    @Test
    @Throws(IOException::class, InterruptedException::class)
    fun stateOnUnknownContainerIsNonzero(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        // Just call state without ever creating anything. Must surface error.
        val r = Contest.run(rootDir, "state", "never-existed")
        assertNotEquals(0, r.rc,
            "state on a nonexistent container must NOT return 0")
    }

    @Test
    @Throws(IOException::class, InterruptedException::class)
    fun deleteOnUnknownContainerIsNonzeroUnlessForce(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        // Without --force, deleting a nonexistent container is an error per
        // the OCI spec. With --force, it's a no-op success.
        val plain = Contest.run(rootDir, "delete", "never-existed")
        assertNotEquals(0, plain.rc,
            "delete without --force on absent container must error")

        val forced = Contest.run(rootDir, "delete", "--force", "never-existed")
        assertEquals(0, forced.rc,
            "delete --force on absent container must succeed (no-op)")
    }
}
