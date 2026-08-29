package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.RecordingSyscalls
import com.ternbusty.takoyaki.syscall.SyscallHost
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Drive Rootfs.applyOciMounts directly via the youki-style RecordingSyscalls
 * fake -- previously impossible because the method was private and reached
 * Libc.mount statics. With the Syscalls trait migration done, every mount(2)
 * the loop issues now becomes a list entry we can pin in order.
 */
class RootfsApplyOciMountsTest {

    companion object {
        private fun mount(dest: String, src: String?, type: String?, options: List<String>?): Mount =
            Mount(destination = dest, source = src, type = type, options = options)
    }

    @Test
    fun wellKnownDestinationsAreSkipped(@TempDir tmp: Path) {
        // /proc, /dev, /sys, /dev/shm, /dev/pts, /dev/mqueue, /sys/fs/cgroup
        // are handled by the dedicated paths in Rootfs.prepare BEFORE the
        // generic loop runs. The generic loop MUST skip them or it would
        // double-mount and the second call would error in mysterious ways.
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
                ), mapOf(), mapOf(), mapOf(), Spec()
            )
        }
        assertTrue(
            rec.mountCalls().isEmpty(),
            "the well-known mount points are skipped by applyOciMounts"
        )
    }

    @Test
    fun nullDestinationIsSkippedNotCrashed(@TempDir tmp: Path) {
        val rec = RecordingSyscalls().stubMountReturn(0)
        val m = Mount() // destination = null
        SyscallHost.install(rec).use {
            assertDoesNotThrow {
                Rootfs.applyOciMounts(
                    tmp.toString(),
                    listOf(m), mapOf(), mapOf(), mapOf(), Spec()
                )
            }
        }
        assertTrue(rec.mountCalls().isEmpty())
    }

    @Test
    fun tmpfsMountIssuesOneCallWithTypeAndData(@TempDir tmp: Path) {
        // Typical /tmp tmpfs in the spec: type=tmpfs, options=["nosuid","mode=755"].
        // Expect ONE mount call: source=tmpfs, target=<rootfs>/tmp, type=tmpfs,
        // flags=MS_NOSUID, data="mode=755". No remount (no bind), no propagation.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/tmp", "tmpfs", "tmpfs", listOf("nosuid", "mode=755"))
                ), mapOf(), mapOf(), mapOf(), Spec()
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
        // The kernel rejects mount(MS_BIND) if fstype is non-null. The OCI
        // spec lets users set type="none" for binds; we must override it to
        // null on the actual syscall.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/data", "/host/data", "none", listOf("bind"))
                ), mapOf(), mapOf(), mapOf(), Spec()
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
        // Critical kernel contract: MS_RDONLY on a fresh bind is silently
        // dropped. To actually enforce read-only on a bind, we MUST issue a
        // second mount with MS_BIND|MS_REMOUNT|MS_RDONLY. Same for nosuid,
        // nodev, noexec, noatime, etc.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/etc/ro", "/host/etc", null, listOf("bind", "ro"))
                ), mapOf(), mapOf(), mapOf(), Spec()
            )
        }
        // Call 1: initial bind. Call 2: remount with MS_RDONLY.
        assertEquals(2, rec.mountCalls().size)
        // First: regular bind, MS_BIND|MS_RDONLY (RDONLY ignored by kernel
        // but we still pass it; this is faithful to spec semantics).
        assertEquals(
            Constants.MS_BIND or Constants.MS_RDONLY,
            rec.mountCalls()[0].flags
        )
        // Second: MS_BIND|MS_REMOUNT|MS_RDONLY targets the SAME target with
        // null source and null type.
        val expected = Constants.MS_BIND or Constants.MS_REMOUNT or Constants.MS_RDONLY
        assertEquals(expected, rec.mountCalls()[1].flags)
        assertNull(rec.mountCalls()[1].source)
        assertNull(rec.mountCalls()[1].fstype)
        assertEquals("${tmp}/etc/ro", rec.mountCalls()[1].target)
    }

    @Test
    fun bindWithoutAccessFlagsDoesNotIssueExtraRemount(@TempDir tmp: Path) {
        // Bind WITHOUT ro/nosuid/nodev/noexec must NOT trigger a remount call.
        // (Otherwise we'd waste a syscall and break some real-world mounts
        // that don't expect MS_REMOUNT.)
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/data", "/host/data", null, listOf("bind"))
                ), mapOf(), mapOf(), mapOf(), Spec()
            )
        }
        assertEquals(
            1, rec.mountCalls().size,
            "plain bind must not be remounted"
        )
    }

    @Test
    fun perMountPropagationGoesInASeparateThirdCall(@TempDir tmp: Path) {
        // Propagation flag (MS_PRIVATE / MS_SHARED / ...) MUST go in its own
        // mount(2) call, NEVER mixed with regular flags. Kernel returns EINVAL
        // if you mix them. This test pins both the "second call is the
        // propagation call" and the "regular flags stayed in call 1" contracts.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount(
                        "/data", "tmpfs", "tmpfs",
                        listOf("nosuid", "rprivate")
                    )
                ), mapOf(), mapOf(), mapOf(), Spec()
            )
        }
        assertEquals(2, rec.mountCalls().size)
        // Call 1: tmpfs with regular MS_NOSUID, NO MS_PRIVATE bit.
        assertEquals(Constants.MS_NOSUID, rec.mountCalls()[0].flags)
        // Call 2: propagation-only.
        assertEquals(
            Constants.MS_PRIVATE or Constants.MS_REC,
            rec.mountCalls()[1].flags
        )
        assertNull(rec.mountCalls()[1].source)
        assertNull(rec.mountCalls()[1].fstype)
    }

    @Test
    fun bindWithRoAndPropagationFiresAllThreeCallsInOrder(@TempDir tmp: Path) {
        // The full sequence: initial bind -> ro remount -> propagation set.
        // We're pinning the ORDER because each kernel call has preconditions
        // (remount must come after bind, propagation must come last).
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount(
                        "/etc/ro", "/host/etc", null,
                        listOf("bind", "ro", "private")
                    )
                ), mapOf(), mapOf(), mapOf(), Spec()
            )
        }
        assertEquals(3, rec.mountCalls().size)
        // Call 1: initial bind, source != null.
        assertEquals("/host/etc", rec.mountCalls()[0].source)
        assertEquals(
            Constants.MS_BIND or Constants.MS_RDONLY,
            rec.mountCalls()[0].flags
        )
        // Call 2: bind+remount+ro.
        assertEquals(
            Constants.MS_BIND or Constants.MS_REMOUNT or Constants.MS_RDONLY,
            rec.mountCalls()[1].flags
        )
        // Call 3: propagation-only.
        assertEquals(Constants.MS_PRIVATE, rec.mountCalls()[2].flags)
    }

    @Test
    fun initialMountFailureSkipsBothRemountAndPropagation(@TempDir tmp: Path) {
        // If the very first mount fails, the test must NOT issue the remount
        // and propagation calls -- they'd target a nonexistent mount and
        // pollute the kernel-side journalctl.
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
                ), mapOf(), mapOf(), mapOf(), Spec()
            )
        }
        assertEquals(
            1, rec.mountCalls().size,
            "remount + propagation must not run when the initial mount failed"
        )
    }

    @Test
    fun multipleMountsAreProcessedInOrder(@TempDir tmp: Path) {
        // A typical bundle has half a dozen mounts. They must execute in
        // the order they appear in spec.mounts -- kernel mount propagation
        // depends on parent-before-child ordering.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount("/tmp", "tmpfs", "tmpfs", listOf("nosuid")),
                    mount("/run", "tmpfs", "tmpfs", listOf("nosuid", "mode=755")),
                    mount("/data", "/host/d", null, listOf("bind"))
                ), mapOf(), mapOf(), mapOf(), Spec()
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
        // Lockdown bind recipe: bind + ro + nosuid + nodev + noexec. The
        // remount must include ALL four access-restricting bits, not just RDONLY.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.applyOciMounts(
                tmp.toString(), listOf(
                    mount(
                        "/data", "/host", null,
                        listOf("bind", "ro", "nosuid", "nodev", "noexec")
                    )
                ), mapOf(), mapOf(), mapOf(), Spec()
            )
        }
        assertEquals(2, rec.mountCalls().size)
        val expected = Constants.MS_BIND or Constants.MS_REMOUNT or
                Constants.MS_RDONLY or Constants.MS_NOSUID or
                Constants.MS_NODEV or Constants.MS_NOEXEC
        assertEquals(expected, rec.mountCalls()[1].flags)
    }
}
