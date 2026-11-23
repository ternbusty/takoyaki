package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls.MountCall;
import com.ternbusty.takoyaki.syscall.SyscallHost;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Mask / readonly-remount tests, rewritten to drive the youki-style
 * {@link RecordingSyscalls} fake instead of Mockito {@code mockStatic(Libc)}.
 * Same assertions, but the recording fake captures the mount(2) argument list
 * directly so we can inspect order, source, target, and flags as data — no
 * verify() incantations.
 */
class RootfsMaskAndReadonlyTest {

    // ---- maskPaths ----------------------------------------------------------

    @Test
    void maskPathsNullIsNoOp() {
        // Spec without maskedPaths must not poke any syscall.
        RecordingSyscalls rec = new RecordingSyscalls();
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(null);
        }
        assertTrue(rec.mountCalls().isEmpty(),
                "null maskedPaths must NOT call mount at all");
    }

    @Test
    void maskPathsBindMountsDevNullOverEachPath() {
        // Per OCI spec, masking a FILE is done by bind-mounting /dev/null over
        // it. Happy path: first mount returns 0 -> no fallback attempted.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of("/proc/kcore", "/sys/firmware"));
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(2, calls.size(), "one mount per path");
        assertEquals("/dev/null",   calls.get(0).source());
        assertEquals("/proc/kcore", calls.get(0).target());
        assertNull  (              calls.get(0).fstype());
        assertEquals(Constants.MS_BIND, calls.get(0).flags());
        assertEquals("/dev/null",   calls.get(1).source());
        assertEquals("/sys/firmware", calls.get(1).target());
    }

    @Test
    void maskPathsFallsBackToTmpfsWhenBindOverFileFailsAndTargetIsDir() {
        // /dev/null is a regular file, so bind-mounting it over a DIRECTORY
        // returns ENOTDIR. The runtime must fall back to mounting an empty
        // tmpfs read-only over the directory.
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)              // both calls return failure...
                .stubErrno(20 /* ENOTDIR */);     // ...but errno != ENOENT so we fall through
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of("/proc/scsi"));
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(2, calls.size(), "must attempt /dev/null bind THEN tmpfs");
        // First attempt: /dev/null bind.
        assertEquals("/dev/null",   calls.get(0).source());
        assertEquals(Constants.MS_BIND, calls.get(0).flags());
        // Second attempt: tmpfs fallback.
        assertEquals("tmpfs",       calls.get(1).source());
        assertEquals("tmpfs",       calls.get(1).fstype());
        assertEquals(Constants.MS_RDONLY, calls.get(1).flags());
        assertEquals("/proc/scsi",  calls.get(1).target());
    }

    @Test
    void maskPathsSkipsTargetThatDoesNotExist() {
        // ENOENT after the first mount means the path isn't in the rootfs.
        // We skip rather than masking nothing or panicking. Critically, the
        // tmpfs fallback must NOT run for ENOENT.
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)
                .stubErrno(Constants.ENOENT);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of("/not/in/rootfs"));
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(1, calls.size(), "tmpfs fallback must NOT run for ENOENT");
        assertEquals("/dev/null", calls.get(0).source());
    }

    @Test
    void maskPathsBothMountsFailingIsLoggedNotThrown() {
        // If even the tmpfs fallback fails, the runtime must not crash. The
        // container still comes up, just without that mask.
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)
                .stubErrno(13 /* EACCES */);
        try (var s = SyscallHost.install(rec)) {
            assertDoesNotThrow(() -> Rootfs.maskPaths(List.of("/proc/sysrq-trigger")));
        }
    }

    // ---- readonlyRemount ----------------------------------------------------

    @Test
    void readonlyRemountNullIsNoOp() {
        RecordingSyscalls rec = new RecordingSyscalls();
        try (var s = SyscallHost.install(rec)) {
            Rootfs.readonlyRemount(null);
        }
        assertTrue(rec.mountCalls().isEmpty());
    }

    @Test
    void readonlyRemountBindsThenRemountsReadOnly() {
        // The runtime contract: first a self-bind (MS_BIND|MS_REC) so the
        // remount won't affect the host, then a remount with MS_RDONLY added.
        // The kernel REQUIRES two calls — MS_RDONLY on a fresh bind is silently
        // dropped.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.readonlyRemount(List.of("/proc/sys"));
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(2, calls.size());
        // Call 1: self-bind, recursive.
        assertEquals("/proc/sys", calls.get(0).source());
        assertEquals("/proc/sys", calls.get(0).target());
        assertEquals(Constants.MS_BIND | Constants.MS_REC, calls.get(0).flags());
        // Call 2: remount with MS_RDONLY.
        long expected = Constants.MS_BIND | Constants.MS_REC
                | Constants.MS_REMOUNT | Constants.MS_RDONLY;
        assertEquals(expected, calls.get(1).flags(),
                "remount must include MS_REMOUNT|MS_RDONLY on top of MS_BIND|MS_REC");
    }

    @Test
    void readonlyRemountSkipsEnoentWithoutAttemptingRemount() {
        // ENOENT on the self-bind means the path isn't in this rootfs. Don't
        // try to remount what we didn't bind.
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)
                .stubErrno(Constants.ENOENT);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.readonlyRemount(List.of("/not/here"));
        }

        // Only ONE call: the failed self-bind. No remount.
        assertEquals(1, rec.mountCalls().size());
        assertEquals(Constants.MS_BIND | Constants.MS_REC,
                rec.mountCalls().get(0).flags());
    }

    @Test
    void maskPathsBindsTheCheckedDevNullByFd() {
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of("/proc/kcore"));
        }
        assertTrue(rec.rawMountCalls().get(0).source().startsWith("/proc/thread-self/fd/"),
                rec.rawMountCalls().get(0).source());
        assertEquals("/dev/null", rec.mountCalls().get(0).source());
    }

    @Test
    void onlyTheNullCharacterDeviceCountsAsDevNull(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp)
            throws Exception {
        assertTrue(Rootfs.isNullDevice("/dev/null"));
        assertFalse(Rootfs.isNullDevice("/dev/zero"), "another character device");
        java.nio.file.Path file = java.nio.file.Files.createFile(tmp.resolve("null"));
        assertFalse(Rootfs.isNullDevice(file.toString()), "a regular file");
        java.nio.file.Path link = java.nio.file.Files.createSymbolicLink(tmp.resolve("link"), file);
        assertFalse(Rootfs.isNullDevice(link.toString()), "a symlink to a regular file");
    }
}
