package com.ternbusty.takoyaki.cgroup

import com.ternbusty.takoyaki.spec.*
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.*
import org.mockito.Mockito.*
import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.*

class CgroupTest {

    @Test
    fun nullCgroupPathIsNoOp() {
        mockStatic(Files::class.java).use { fm ->
            Cgroup.setup(123, null, null)
            fm.verifyNoInteractions()
        }
    }

    @Test
    fun leadingSlashIsStrippedBeforeResolving() {
        // We accept both "/takoyaki-x" and "takoyaki-x" from the spec. The
        // resulting cgroup path must be /sys/fs/cgroup/takoyaki-x either way.
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.createDirectories(any()) }.thenReturn(null)
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")

            Cgroup.setup(123, "/takoyaki-x", null)
            fm.verify { Files.createDirectories(
                eq(Path.of("/sys/fs/cgroup/takoyaki-x"))) }
            fm.verify { Files.writeString(
                eq(Path.of("/sys/fs/cgroup/takoyaki-x/cgroup.procs")),
                eq("123")) }
        }
    }

    @Test
    fun memoryLimitWritesMemoryMax() {
        // Confirm spec.linux.resources.memory.limit lands at memory.max with
        // the exact value (or "max" sentinel for -1).
        val r = LinuxResources(memory = LinuxMemory(limit = 67108864L)) // 64 MiB

        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.createDirectories(any()) }.thenReturn(null)
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")
            val linux = Linux(resources = r)
            Cgroup.setup(123, "/takoyaki-mem", linux)

            fm.verify { Files.writeString(
                eq(Path.of("/sys/fs/cgroup/takoyaki-mem/memory.max")),
                eq("67108864")) }
        }
    }

    @Test
    fun memoryMinusOneLimitWritesMaxSentinel() {
        val r = LinuxResources(memory = LinuxMemory(limit = -1L))

        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.createDirectories(any()) }.thenReturn(null)
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")
            val linux = Linux(resources = r)
            Cgroup.setup(123, "/takoyaki-mem", linux)

            fm.verify { Files.writeString(
                eq(Path.of("/sys/fs/cgroup/takoyaki-mem/memory.max")),
                eq("max")) }
        }
    }

    @Test
    fun cpuCpusetIsApplied() {
        val r = LinuxResources(cpu = LinuxCpu(cpus = "0-1"))

        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.createDirectories(any()) }.thenReturn(null)
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")
            val linux = Linux(resources = r)
            Cgroup.setup(123, "/takoyaki-cpu", linux)

            fm.verify { Files.writeString(
                eq(Path.of("/sys/fs/cgroup/takoyaki-cpu/cpuset.cpus")),
                eq("0-1")) }
        }
    }

    @Test
    fun cpuQuotaAndPeriodAreCombinedIntoCpuMax() {
        // cgroup v2 writes both as one string "quota period".
        val r = LinuxResources(cpu = LinuxCpu(quota = 50000L, period = 100000L))

        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.createDirectories(any()) }.thenReturn(null)
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")
            val linux = Linux(resources = r)
            Cgroup.setup(123, "/takoyaki-q", linux)

            fm.verify { Files.writeString(
                eq(Path.of("/sys/fs/cgroup/takoyaki-q/cpu.max")),
                eq("50000 100000")) }
        }
    }

    @Test
    fun pidsLimitIsDeferredDuringSetup() {
        // pids.max is deferred during setup() so the GraalVM init process
        // can create threads. applyDeferredPids() writes it after INIT_READY.
        val r = LinuxResources(pids = LinuxPids(limit = 100))

        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.createDirectories(any()) }.thenReturn(null)
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")
            val linux = Linux(resources = r)
            Cgroup.setup(123, "/takoyaki-p", linux)

            // pids.max must NOT be written during setup.
            fm.verify({ Files.writeString(
                eq(Path.of("/sys/fs/cgroup/takoyaki-p/pids.max")),
                anyString()) }, never())
        }
    }

    @Test
    fun applyDeferredPidsWritesPidsMax() {
        val r = LinuxResources(pids = LinuxPids(limit = 100))

        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            Cgroup.applyDeferredPids("/takoyaki-p", r)

            fm.verify { Files.writeString(
                eq(Path.of("/sys/fs/cgroup/takoyaki-p/pids.max")),
                eq("100")) }
        }
    }

    @Test
    fun enableControllersWalksParentChainTowardsRoot() {
        // For a nested cgroup like /takoyaki/sub the runtime must "+memory"
        // (etc.) in EACH ancestor's cgroup.subtree_control. Verify that
        // subtree_control writes hit at least the root.
        val r = LinuxResources(memory = LinuxMemory(limit = 4096L))

        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.createDirectories(any()) }.thenReturn(null)
            fm.`when`<Any> { Files.writeString(any(), anyString()) }.thenReturn(Path.of("/dev/null"))
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")
            val linux = Linux(resources = r)
            Cgroup.setup(123, "/takoyaki/sub", linux)

            // The root cgroup must get a "+memory" write.
            fm.verify { Files.writeString(
                eq(Path.of("/sys/fs/cgroup/cgroup.subtree_control")),
                eq("+memory")) }
        }
    }

    @Test
    fun cleanupRemovesDirectoryWhenItExists() {
        // The cleanup path is: write '1' to cgroup.kill -> retry rmdir until
        // it succeeds (or the deadline). On the happy path Files.delete
        // succeeds on the first attempt.
        mockStatic(Files::class.java).use { fm ->
            val cgDir = Path.of("/sys/fs/cgroup/takoyaki-x")
            fm.`when`<Any> { Files.exists(eq(cgDir)) }.thenReturn(true)
            fm.`when`<Any> { Files.writeString(any(Path::class.java), anyString()) }
                .thenReturn(cgDir)
            fm.`when`<Any> { Files.readString(any()) }.thenReturn("")
            // Files.delete returns void; the default (no stub) is to do nothing
            // and return successfully, which matches the happy path.

            Cgroup.cleanup("/takoyaki-x")

            fm.verify { Files.writeString(
                eq(cgDir.resolve("cgroup.kill")), eq("1")) }
            fm.verify { Files.delete(eq(cgDir)) }
        }
    }

    @Test
    fun cleanupSkipsEverythingWhenDirectoryDoesNotExist() {
        // No directory -> nothing to kill, nothing to poll, nothing to delete.
        // (Early return short-circuits the cgroup.kill write too.)
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Any> { Files.exists(any()) }.thenReturn(false)
            Cgroup.cleanup("/takoyaki-x")
            fm.verify({ Files.delete(any()) }, never())
            fm.verify({ Files.writeString(any(Path::class.java), anyString()) }, never())
        }
    }

    @Test
    fun cleanupNullIsNoOp() {
        mockStatic(Files::class.java).use { fm ->
            Cgroup.cleanup(null)
            fm.verifyNoInteractions()
        }
    }
}
