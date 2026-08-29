package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.spec.*
import io.mockk.every
import io.mockk.just
import io.mockk.mockkObject
import io.mockk.runs
import io.mockk.slot
import io.mockk.unmockkObject
import io.mockk.verify
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

class UpdateCommandTest {

    @Test
    fun returnsErrorWhenNoKontainerConfigExists(@TempDir tmp: Path) {
        // update against an unknown id must NOT silently succeed — Cgroup
        // wouldn't know where to write. We surface non-zero.
        mockkObject(Cgroup)
        try {
            val rc = UpdateCommand.run(tmp.toString(), "absent",
                null, null, null, null, null, null,
                null, null, null, null, null)
            assertEquals(1, rc)
            verify(exactly = 0) { Cgroup.applyLimitsOnly(any(), any()) }
        } finally {
            unmockkObject(Cgroup)
        }
    }

    @Test
    @Throws(IOException::class)
    fun returnsErrorWhenConfigHasNullCgroupPath(@TempDir tmp: Path) {
        KontainerConfig(null).save(tmp.toString(), "no-cgroup")
        mockkObject(Cgroup)
        try {
            val rc = UpdateCommand.run(tmp.toString(), "no-cgroup",
                null, null, null, null, null, null,
                null, null, null, null, null)
            assertEquals(1, rc)
            verify(exactly = 0) { Cgroup.applyLimitsOnly(any(), any()) }
        } finally {
            unmockkObject(Cgroup)
        }
    }

    @Test
    @Throws(IOException::class)
    fun memoryFlagOnlyPopulatesMemoryLimit(@TempDir tmp: Path) {
        KontainerConfig("/sys/fs/cgroup/user.slice/x")
            .save(tmp.toString(), "ctr")

        mockkObject(Cgroup)
        try {
            every { Cgroup.applyLimitsOnly(any(), any()) } just runs

            val rc = UpdateCommand.run(tmp.toString(), "ctr",
                null, 256L * 1024 * 1024, null, null,
                null, null, null, null, null, null, null)
            assertEquals(0, rc)
            val arg = slot<LinuxResources>()
            verify { Cgroup.applyLimitsOnly(
                eq("/sys/fs/cgroup/user.slice/x"), capture(arg)) }
            val r = arg.captured
            // Only memory.limit should be populated. cpu/pids must stay null
            // so applyLimitsOnly knows not to touch their controllers.
            assertNotNull(r.memory, "memory block must be created")
            assertEquals(256L * 1024 * 1024, r.memory!!.limit)
            assertNull(r.cpu)
            assertNull(r.pids)
        } finally {
            unmockkObject(Cgroup)
        }
    }

    @Test
    @Throws(IOException::class)
    fun cpuFlagsAllPopulateCpuBlock(@TempDir tmp: Path) {
        KontainerConfig("/sys/fs/cgroup/x").save(tmp.toString(), "ctr")

        mockkObject(Cgroup)
        try {
            every { Cgroup.applyLimitsOnly(any(), any()) } just runs

            val rc = UpdateCommand.run(tmp.toString(), "ctr",
                null, null, null, null,
                50000L, 100000L, 1024L, null, null, null, null)
            assertEquals(0, rc)
            val arg = slot<LinuxResources>()
            verify { Cgroup.applyLimitsOnly(any(), capture(arg)) }
            val r = arg.captured
            assertNotNull(r.cpu)
            assertEquals(50000L, r.cpu!!.quota)
            assertEquals(100000L, r.cpu!!.period)
            assertEquals(1024L, r.cpu!!.shares)
            // memory/pids not touched.
            assertNull(r.memory)
            assertNull(r.pids)
        } finally {
            unmockkObject(Cgroup)
        }
    }

    @Test
    @Throws(IOException::class)
    fun pidsLimitFlagPopulatesPidsBlock(@TempDir tmp: Path) {
        KontainerConfig("/sys/fs/cgroup/x").save(tmp.toString(), "ctr")

        mockkObject(Cgroup)
        try {
            every { Cgroup.applyLimitsOnly(any(), any()) } just runs

            val rc = UpdateCommand.run(tmp.toString(), "ctr",
                null, null, null, null, null, null,
                null, 512L, null, null, null)
            assertEquals(0, rc)
            val arg = slot<LinuxResources>()
            verify { Cgroup.applyLimitsOnly(any(), capture(arg)) }
            assertNotNull(arg.captured.pids)
            assertEquals(512L, arg.captured.pids!!.limit)
        } finally {
            unmockkObject(Cgroup)
        }
    }

    @Test
    @Throws(IOException::class)
    fun resourcesJsonFileIsLoadedAndOverriddenByFlags(@TempDir tmp: Path) {
        // --resources reads a full LinuxResources JSON. Flags then OVERRIDE
        // matching fields. Both runc and youki document this precedence.
        KontainerConfig("/sys/fs/cgroup/x").save(tmp.toString(), "ctr")
        val res = tmp.resolve("resources.json")
        Files.writeString(res, """{"memory":{"limit":100},"pids":{"limit":42}}""")

        mockkObject(Cgroup)
        try {
            every { Cgroup.applyLimitsOnly(any(), any()) } just runs

            val rc = UpdateCommand.run(tmp.toString(), "ctr",
                res.toString(), 999L, null, null,
                null, null, null, null, null, null, null)
            assertEquals(0, rc)
            val arg = slot<LinuxResources>()
            verify { Cgroup.applyLimitsOnly(any(), capture(arg)) }
            val r = arg.captured
            // flag wins
            assertEquals(999L, r.memory!!.limit)
            // file-only value kept
            assertEquals(42L, r.pids!!.limit)
        } finally {
            unmockkObject(Cgroup)
        }
    }

    @Test
    @Throws(IOException::class)
    fun invalidResourcesFileReturnsErrorAndDoesNotApply(@TempDir tmp: Path) {
        KontainerConfig("/sys/fs/cgroup/x").save(tmp.toString(), "ctr")

        mockkObject(Cgroup)
        try {
            val rc = UpdateCommand.run(tmp.toString(), "ctr",
                tmp.resolve("does-not-exist.json").toString(),
                null, null, null, null, null,
                null, null, null, null, null)
            assertEquals(1, rc)
            verify(exactly = 0) { Cgroup.applyLimitsOnly(any(), any()) }
        } finally {
            unmockkObject(Cgroup)
        }
    }
}
