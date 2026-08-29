package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.RecordingSyscalls
import com.ternbusty.takoyaki.syscall.SyscallHost
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class RootfsApplyOciMountsTest {

    companion object {
        private fun mount(dest: String, src: String?, type: String?, options: List<String>?): Mount =
            Mount(destination = dest, source = src, type = type, options = options)

        private fun dummySpec(): Spec = Spec(root = Root(path = "/rootfs"))
    }

    @Test
    fun wellKnownDestinationsAreSkipped(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/proc", "proc", "proc", null),
                    mount("/dev", "tmpfs", "tmpfs", null),
                    mount("/sys", "sysfs", "sysfs", null),
                    mount("/dev/shm", "shm", "tmpfs", null),
                    mount("/dev/pts", "devpts", "devpts", null),
                    mount("/dev/mqueue", "mqueue", "mqueue", null),
                    mount("/sys/fs/cgroup", "cgroup", "cgroup2", null)
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertTrue(
            rec.mountCalls().isEmpty(),
            "the well-known mount points are skipped by applyOciMounts"
        )
    }

    @Test
    fun tmpfsMountIssuesOneCallWithTypeAndData(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/tmp", "tmpfs", "tmpfs", listOf("nosuid", "mode=755"))
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }

        assertEquals(1, rec.mountCalls().size)
        val c = rec.mountCalls()[0]
        assertEquals("tmpfs", c.source)
        assertEquals("${tmp}/tmp", c.target)
        assertEquals("tmpfs", c.fstype)
        assertEquals(Constants.MS_NOSUID, c.flags)
        assertEquals("mode=755", c.data)
    }

    @Test
    fun bindMountPassesNullTypeNotTheSpecType(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/data", "/host/data", "none", listOf("bind"))
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertEquals(1, rec.mountCalls().size)
        assertNull(
            rec.mountCalls()[0].fstype,
            "bind mounts MUST pass NULL fstype to mount(2)"
        )
        assertEquals("/host/data", rec.mountCalls()[0].source)
        assertEquals(Constants.MS_BIND, rec.mountCalls()[0].flags)
    }

    @Test
    fun bindWithReadOnlyTriggersSecondRemountCallWithMsRemount(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/etc/ro", "/host/etc", null, listOf("bind", "ro"))
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertEquals(2, rec.mountCalls().size)
        assertEquals(
            Constants.MS_BIND or Constants.MS_RDONLY,
            rec.mountCalls()[0].flags
        )
        val expected = Constants.MS_BIND or Constants.MS_REMOUNT or Constants.MS_RDONLY
        assertEquals(expected, rec.mountCalls()[1].flags)
        assertNull(rec.mountCalls()[1].source)
        assertNull(rec.mountCalls()[1].fstype)
        assertEquals("${tmp}/etc/ro", rec.mountCalls()[1].target)
    }

    @Test
    fun bindWithoutAccessFlagsDoesNotIssueExtraRemount(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/data", "/host/data", null, listOf("bind"))
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertEquals(
            1, rec.mountCalls().size,
            "plain bind must not be remounted"
        )
    }

    @Test
    fun perMountPropagationGoesInASeparateThirdCall(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount(
                        "/data", "tmpfs", "tmpfs",
                        listOf("nosuid", "rprivate")
                    )
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertEquals(2, rec.mountCalls().size)
        assertEquals(Constants.MS_NOSUID, rec.mountCalls()[0].flags)
        assertEquals(
            Constants.MS_PRIVATE or Constants.MS_REC,
            rec.mountCalls()[1].flags
        )
        assertNull(rec.mountCalls()[1].source)
        assertNull(rec.mountCalls()[1].fstype)
    }

    @Test
    fun bindWithRoAndPropagationFiresAllThreeCallsInOrder(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount(
                        "/etc/ro", "/host/etc", null,
                        listOf("bind", "ro", "private")
                    )
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertEquals(3, rec.mountCalls().size)
        assertEquals("/host/etc", rec.mountCalls()[0].source)
        assertEquals(
            Constants.MS_BIND or Constants.MS_RDONLY,
            rec.mountCalls()[0].flags
        )
        assertEquals(
            Constants.MS_BIND or Constants.MS_REMOUNT or Constants.MS_RDONLY,
            rec.mountCalls()[1].flags
        )
        assertEquals(Constants.MS_PRIVATE, rec.mountCalls()[2].flags)
    }

    @Test
    fun initialMountFailureSkipsBothRemountAndPropagation(@TempDir tmp: Path) {
        val rec = RecordingSyscalls()
            .stubMountReturn(-1)
            .stubErrno(13 /* EACCES */)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount(
                        "/etc/ro", "/host/etc", null,
                        listOf("bind", "ro", "private")
                    )
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertEquals(
            1, rec.mountCalls().size,
            "remount + propagation must not run when the initial mount failed"
        )
    }

    @Test
    fun multipleMountsAreProcessedInOrder(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/tmp", "tmpfs", "tmpfs", listOf("nosuid")),
                    mount("/run", "tmpfs", "tmpfs", listOf("nosuid", "mode=755")),
                    mount("/data", "/host/d", null, listOf("bind"))
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }

        val calls = rec.mountCalls()
        assertEquals(3, calls.size)
        assertEquals("${tmp}/tmp", calls[0].target)
        assertEquals("${tmp}/run", calls[1].target)
        assertEquals("${tmp}/data", calls[2].target)
    }

    @Test
    fun nosuidNodevNoexecAllPropagateToRemountFlags(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount(
                        "/data", "/host", null,
                        listOf("bind", "ro", "nosuid", "nodev", "noexec")
                    )
                ), mapOf(), mapOf(), mapOf(), dummySpec()
            )
        }
        assertEquals(2, rec.mountCalls().size)
        val expected = Constants.MS_BIND or Constants.MS_REMOUNT or
                Constants.MS_RDONLY or Constants.MS_NOSUID or
                Constants.MS_NODEV or Constants.MS_NOEXEC
        assertEquals(expected, rec.mountCalls()[1].flags)
    }
}
