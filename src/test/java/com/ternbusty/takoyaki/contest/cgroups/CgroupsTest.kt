package com.ternbusty.takoyaki.contest.cgroups

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * cgroup v2 family. Each test sets a specific resource limit in
 * spec.linux.resources, then verifies the kernel-facing file under
 * /sys/fs/cgroup/{cgroupsPath}/ ends up with the expected value.
 *
 * These are HOST-OBSERVABLE: cgroup files are visible from the runtime
 * namespace; we don't need to be inside the container to read them. The
 * file content IS the conformance point — the kernel will enforce whatever
 * is written there regardless of whether the container is started.
 */
@Contest.RequiresTakoyaki
class CgroupsTest {

    @Test
    fun cgroupsPathDirectoryIsCreated(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val cgPath = "/takoyaki-test-${System.nanoTime()}"

        Contest.writeBundle(bundle, baseSpec(cgPath, emptyMap()))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) { "create failed: ${create.stderr}" }

        // The leaf cgroup directory must exist after create.
        val cgDir = Path.of("/sys/fs/cgroup$cgPath")
        assertTrue(Files.isDirectory(cgDir)) {
            "cgroup directory $cgDir was not created. create stderr: ${create.stderr}"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }

    @Test
    fun memoryLimitIsWrittenToMemoryMax(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val cgPath = "/takoyaki-test-${System.nanoTime()}"
        val memLimit = 64L * 1024 * 1024 // 64 MB

        Contest.writeBundle(bundle, baseSpec(cgPath, mapOf(
            "memory" to mapOf("limit" to memLimit)
        )))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) { "create failed: ${create.stderr}" }

        val memMax = Path.of("/sys/fs/cgroup$cgPath/memory.max")
        assertTrue(Files.exists(memMax)) { "memory.max not created at $memMax" }

        val content = Files.readString(memMax).trim()
        assertEquals(memLimit.toString(), content) {
            "memory.max expected $memLimit but was <$content>"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }

    @Test
    fun pidsLimitIsWrittenToPidsMax(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val cgPath = "/takoyaki-test-${System.nanoTime()}"

        Contest.writeBundle(bundle, baseSpec(cgPath, mapOf(
            "pids" to mapOf("limit" to 100)
        )))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) { "create failed: ${create.stderr}" }

        val pidsMax = Path.of("/sys/fs/cgroup$cgPath/pids.max")
        assertTrue(Files.exists(pidsMax)) { "pids.max not created at $pidsMax" }

        val content = Files.readString(pidsMax).trim()
        assertEquals("100", content) { "pids.max expected 100 but was <$content>" }

        Contest.run(rootDir, "delete", "--force", id)
    }

    @Test
    fun cpuPeriodAndQuotaAreWrittenToCpuMax(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val cgPath = "/takoyaki-test-${System.nanoTime()}"

        // cgroup v2 packs both quota and period into cpu.max as one line:
        // "<quota> <period>". Setting quota=50000 period=100000 means 0.5 CPU.
        Contest.writeBundle(bundle, baseSpec(cgPath, mapOf(
            "cpu" to mapOf("period" to 100000, "quota" to 50000)
        )))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) { "create failed: ${create.stderr}" }

        val cpuMax = Path.of("/sys/fs/cgroup$cgPath/cpu.max")
        assertTrue(Files.exists(cpuMax))

        val content = Files.readString(cpuMax).trim()
        assertEquals("50000 100000", content) {
            "cpu.max expected '50000 100000' but was <$content>"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }

    @Test
    fun cgroupDirectoryIsRemovedAfterDelete(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")
        val cgPath = "/takoyaki-test-${System.nanoTime()}"

        Contest.writeBundle(bundle, baseSpec(cgPath, emptyMap()))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc)

        val cgDir = Path.of("/sys/fs/cgroup$cgPath")
        assertTrue(Files.isDirectory(cgDir))

        val delete = Contest.run(rootDir, "delete", "--force", id)
        assertEquals(0, delete.rc)

        // After delete, the cgroup MUST be reaped. Stale cgroups
        // are a long-running OOM-killer leak source for orchestrators
        // that don't reap them themselves.
        //
        // Tiny poll: cgroup tear-down has an unavoidable async tail in the
        // kernel (cgroup_destroy_locked schedules work). Even after takoyaki
        // returns successfully, the directory entry can survive ~10-50 ms on
        // fast hosts. Wait up to 2 seconds for it to disappear before
        // declaring a leak.
        val deadline = System.nanoTime() + 2_000_000_000L
        while (System.nanoTime() < deadline && Files.exists(cgDir)) {
            Thread.sleep(50)
        }
        assertFalse(Files.exists(cgDir)) {
            "cgroup directory $cgDir leaked after delete. delete stderr: ${delete.stderr}"
        }
    }

    companion object {
        private fun baseSpec(
            cgroupsPath: String,
            resources: Map<String, Any>
        ): Map<String, Any> {
            val linux = linkedMapOf<String, Any>(
                "cgroupsPath" to cgroupsPath,
                "namespaces" to listOf(
                    mapOf("type" to "pid"),
                    mapOf("type" to "mount"),
                    mapOf("type" to "ipc"),
                    mapOf("type" to "uts"),
                    mapOf("type" to "cgroup")
                )
            )
            if (resources.isNotEmpty()) {
                linux["resources"] = resources
            }
            return mapOf(
                "ociVersion" to "1.0.0",
                "process" to mapOf(
                    "terminal" to false,
                    "args" to listOf("/bin/true"),
                    "cwd" to "/",
                    "user" to mapOf("uid" to 0, "gid" to 0)
                ),
                "root" to mapOf("path" to "rootfs"),
                "linux" to linux
            )
        }
    }
}
