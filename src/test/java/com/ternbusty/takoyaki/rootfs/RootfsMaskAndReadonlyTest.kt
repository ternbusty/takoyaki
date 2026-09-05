package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.RecordingSyscalls
import com.ternbusty.takoyaki.syscall.SyscallHost
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Mask / readonly-remount tests, rewritten to drive the youki-style
 * [RecordingSyscalls] fake instead of Mockito `mockStatic(Libc)`.
 * Same assertions, but the recording fake captures the mount(2) argument list
 * directly so we can inspect order, source, target, and flags as data -- no
 * verify() incantations.
 */
class RootfsMaskAndReadonlyTest {

    // ---- maskPaths ----------------------------------------------------------

    @Test
    fun maskPathsNullIsNoOp() {
        // Spec without maskedPaths must not poke any syscall.
        val rec = RecordingSyscalls()
        SyscallHost.install(rec).use {
            Rootfs.maskPaths(null)
        }
        assertTrue(
            rec.mountCalls().isEmpty(),
            "null maskedPaths must NOT call mount at all"
        )
    }

    @Test
    fun maskPathsBindMountsDevNullOverEachPath() {
        // Per OCI spec, masking a FILE is done by bind-mounting /dev/null over
        // it. Happy path: first mount returns 0 -> no fallback attempted.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.maskPaths(listOf("/proc/kcore", "/sys/firmware"))
        }

        val calls = rec.mountCalls()
        assertEquals(2, calls.size, "one mount per path")
        assertEquals("/dev/null", calls[0].source)
        assertEquals("/proc/kcore", calls[0].target)
        assertNull(calls[0].fstype)
        assertEquals(Constants.MS_BIND, calls[0].flags)
        assertEquals("/dev/null", calls[1].source)
        assertEquals("/sys/firmware", calls[1].target)
    }

    @Test
    fun maskPathsFallsBackToTmpfsWhenBindOverFileFailsAndTargetIsDir() {
        // /dev/null is a regular file, so bind-mounting it over a DIRECTORY
        // returns ENOTDIR. The runtime must fall back to mounting an empty
        // tmpfs read-only over the directory.
        val rec = RecordingSyscalls()
            .stubMountReturn(-1)             // both calls return failure...
            .stubErrno(20 /* ENOTDIR */)     // ...but errno != ENOENT so we fall through
        SyscallHost.install(rec).use {
            Rootfs.maskPaths(listOf("/proc/scsi"))
        }

        val calls = rec.mountCalls()
        assertEquals(2, calls.size, "must attempt /dev/null bind THEN tmpfs")
        // First attempt: /dev/null bind.
        assertEquals("/dev/null", calls[0].source)
        assertEquals(Constants.MS_BIND, calls[0].flags)
        // Second attempt: tmpfs fallback.
        assertEquals("tmpfs", calls[1].source)
        assertEquals("tmpfs", calls[1].fstype)
        assertEquals(Constants.MS_RDONLY, calls[1].flags)
        assertEquals("/proc/scsi", calls[1].target)
    }

    @Test
    fun maskPathsSkipsTargetThatDoesNotExist() {
        // ENOENT after the first mount means the path isn't in the rootfs.
        // We skip rather than masking nothing or panicking. Critically, the
        // tmpfs fallback must NOT run for ENOENT.
        val rec = RecordingSyscalls()
            .stubMountReturn(-1)
            .stubErrno(Constants.ENOENT)
        SyscallHost.install(rec).use {
            Rootfs.maskPaths(listOf("/not/in/rootfs"))
        }

        val calls = rec.mountCalls()
        assertEquals(1, calls.size, "tmpfs fallback must NOT run for ENOENT")
        assertEquals("/dev/null", calls[0].source)
    }

    @Test
    fun maskPathsBothMountsFailingIsLoggedNotThrown() {
        // If even the tmpfs fallback fails, the runtime must not crash. The
        // container still comes up, just without that mask.
        val rec = RecordingSyscalls()
            .stubMountReturn(-1)
            .stubErrno(13 /* EACCES */)
        SyscallHost.install(rec).use {
            assertDoesNotThrow { Rootfs.maskPaths(listOf("/proc/sysrq-trigger")) }
        }
    }

    // ---- readonlyRemount ----------------------------------------------------

    @Test
    fun readonlyRemountNullIsNoOp() {
        val rec = RecordingSyscalls()
        SyscallHost.install(rec).use {
            Rootfs.readonlyRemount(null)
        }
        assertTrue(rec.mountCalls().isEmpty())
    }

    @Test
    fun readonlyRemountBindsThenRemountsReadOnly() {
        // The runtime contract: first a self-bind (MS_BIND|MS_REC) so the
        // remount won't affect the host, then a remount with MS_RDONLY added.
        // The kernel REQUIRES two calls -- MS_RDONLY on a fresh bind is silently
        // dropped.
        val rec = RecordingSyscalls().stubMountReturn(0)
        SyscallHost.install(rec).use {
            Rootfs.readonlyRemount(listOf("/proc/sys"))
        }

        val calls = rec.mountCalls()
        assertEquals(2, calls.size)
        // Call 1: self-bind, recursive.
        assertEquals("/proc/sys", calls[0].source)
        assertEquals("/proc/sys", calls[0].target)
        assertEquals(Constants.MS_BIND or Constants.MS_REC, calls[0].flags)
        // Call 2: remount with MS_RDONLY.
        val expected = Constants.MS_BIND or Constants.MS_REC or
                Constants.MS_REMOUNT or Constants.MS_RDONLY
        assertEquals(
            expected, calls[1].flags,
            "remount must include MS_REMOUNT|MS_RDONLY on top of MS_BIND|MS_REC"
        )
    }

    @Test
    fun readonlyRemountSkipsEnoentWithoutAttemptingRemount() {
        // ENOENT on the self-bind means the path isn't in this rootfs. Don't
        // try to remount what we didn't bind.
        val rec = RecordingSyscalls()
            .stubMountReturn(-1)
            .stubErrno(Constants.ENOENT)
        SyscallHost.install(rec).use {
            Rootfs.readonlyRemount(listOf("/not/here"))
        }

        // Only ONE call: the failed self-bind. No remount.
        assertEquals(1, rec.mountCalls().size)
        assertEquals(
            Constants.MS_BIND or Constants.MS_REC,
            rec.mountCalls()[0].flags
        )
    }
}
