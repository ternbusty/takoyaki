package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls.MountCall;
import com.ternbusty.takoyaki.syscall.SyscallHost;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Mask / readonly-remount tests, rewritten to drive the youki-style
 * {@link RecordingSyscalls} fake instead of Mockito {@code mockStatic(Libc)}.
 * Same assertions, but the recording fake captures the mount(2) argument list
 * directly so we can inspect order, source, target, and flags as data — no
 * verify() incantations.
 *
 * <p>The paths are opened for real (the mounts go to their fds), so the tests
 * mask files and directories under a temporary directory.
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
    void maskPathsBindMountsDevNullOverEachPath(@TempDir Path tmp) throws Exception {
        // Per OCI spec, masking a FILE is done by bind-mounting /dev/null over
        // it. Happy path: first mount returns 0 -> no fallback attempted.
        String kcore = Files.createFile(tmp.resolve("kcore")).toString();
        String firmware = Files.createFile(tmp.resolve("firmware")).toString();
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of(kcore, firmware));
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(2, calls.size(), "one mount per path");
        assertEquals("/dev/null",   calls.get(0).source());
        assertEquals(kcore,         calls.get(0).target());
        assertNull  (              calls.get(0).fstype());
        assertEquals(Constants.MS_BIND, calls.get(0).flags());
        assertEquals("/dev/null",   calls.get(1).source());
        assertEquals(firmware,      calls.get(1).target());
    }

    @Test
    void maskPathsFallsBackToTmpfsWhenBindOverFileFailsAndTargetIsDir(@TempDir Path tmp)
            throws Exception {
        // /dev/null is a regular file, so bind-mounting it over a DIRECTORY
        // returns ENOTDIR. The runtime must fall back to mounting an empty
        // tmpfs read-only over the directory.
        String scsi = Files.createDirectory(tmp.resolve("scsi")).toString();
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)              // both calls return failure
                .stubErrno(20 /* ENOTDIR */);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of(scsi));
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
        assertEquals(scsi,          calls.get(1).target());
    }

    @Test
    void maskPathsSkipsTargetThatDoesNotExist(@TempDir Path tmp) {
        // A path that isn't in the rootfs cannot be opened: it is skipped,
        // with no mount at all (and so no tmpfs fallback either).
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of(tmp.resolve("not/in/rootfs").toString()));
        }

        assertTrue(rec.mountCalls().isEmpty(), "nothing to mask, nothing mounted");
    }

    @Test
    void laterDirectoryMasksBindTheFirstTmpfs(@TempDir Path tmp) throws Exception {
        // runc compat: one tmpfs for all directory masks. The /dev/null bind
        // fails for each directory (ENOTDIR); the first gets the tmpfs, the
        // others a bind of it.
        String a = Files.createDirectory(tmp.resolve("a")).toString();
        String b = Files.createDirectory(tmp.resolve("b")).toString();
        int[] n = {0};
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(() -> (n[0]++ % 2 == 0) ? -1 : 0)
                .stubErrno(20 /* ENOTDIR */);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of(a, b));
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(4, calls.size());
        assertEquals("tmpfs", calls.get(1).fstype());
        assertEquals(a, calls.get(1).target());
        assertEquals(a, calls.get(3).source(), "the tmpfs on the first directory");
        assertEquals(b, calls.get(3).target());
        assertEquals(Constants.MS_BIND | Constants.MS_RDONLY, calls.get(3).flags());
    }

    @Test
    void maskPathsBothMountsFailingIsLoggedNotThrown(@TempDir Path tmp) throws Exception {
        // If even the tmpfs fallback fails, the runtime must not crash. The
        // container still comes up, just without that mask.
        String trigger = Files.createFile(tmp.resolve("sysrq-trigger")).toString();
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)
                .stubErrno(13 /* EACCES */);
        try (var s = SyscallHost.install(rec)) {
            assertDoesNotThrow(() -> Rootfs.maskPaths(List.of(trigger)));
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
    void readonlyRemountBindsThenRemountsReadOnly(@TempDir Path tmp) throws Exception {
        // The runtime contract: first a self-bind (MS_BIND|MS_REC) so the
        // remount won't affect the host, then a remount with MS_RDONLY added.
        // The kernel REQUIRES two calls — MS_RDONLY on a fresh bind is silently
        // dropped.
        String sys = Files.createDirectory(tmp.resolve("sys")).toString();
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.readonlyRemount(List.of(sys));
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(2, calls.size());
        // Call 1: self-bind, recursive.
        assertEquals(sys, calls.get(0).source());
        assertEquals(sys, calls.get(0).target());
        assertEquals(Constants.MS_BIND | Constants.MS_REC, calls.get(0).flags());
        // Call 2: remount with MS_RDONLY.
        long expected = Constants.MS_BIND | Constants.MS_REC
                | Constants.MS_REMOUNT | Constants.MS_RDONLY;
        assertEquals(expected, calls.get(1).flags(),
                "remount must include MS_REMOUNT|MS_RDONLY on top of MS_BIND|MS_REC");
        assertEquals(sys, calls.get(1).target());
        // Both go to the path's fd, the remount to the bind re-opened.
        assertTrue(rec.rawMountCalls().get(0).target().startsWith("/proc/thread-self/fd/"));
        assertTrue(rec.rawMountCalls().get(1).target().startsWith("/proc/thread-self/fd/"));
        assertNotEquals(rec.rawMountCalls().get(0).target(), rec.rawMountCalls().get(1).target());
    }

    @Test
    void readonlyRemountSkipsMissingPathWithoutMounting(@TempDir Path tmp) {
        // A path that isn't in this rootfs cannot be opened: no bind, no remount.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.readonlyRemount(List.of(tmp.resolve("not/here").toString()));
        }

        assertTrue(rec.mountCalls().isEmpty());
    }

    @Test
    void readonlyRemountIsNotAttemptedWhenTheBindFails(@TempDir Path tmp) throws Exception {
        String sys = Files.createDirectory(tmp.resolve("sys")).toString();
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)
                .stubErrno(13 /* EACCES */);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.readonlyRemount(List.of(sys));
        }

        // Only ONE call: the failed self-bind. No remount.
        assertEquals(1, rec.mountCalls().size());
        assertEquals(Constants.MS_BIND | Constants.MS_REC,
                rec.mountCalls().get(0).flags());
    }

    @Test
    void maskPathsBindsTheCheckedDevNullByFd(@TempDir Path tmp) throws Exception {
        String kcore = Files.createFile(tmp.resolve("kcore")).toString();
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.maskPaths(List.of(kcore));
        }
        MountCall raw = rec.rawMountCalls().get(0);
        assertTrue(raw.source().startsWith("/proc/thread-self/fd/"), raw.source());
        assertTrue(raw.target().startsWith("/proc/thread-self/fd/"), raw.target());
        assertEquals("/dev/null", rec.mountCalls().get(0).source());
    }

    @Test
    void onlyTheNullCharacterDeviceCountsAsDevNull(@TempDir Path tmp) throws Exception {
        assertTrue(Rootfs.isNullDevice("/dev/null"));
        assertFalse(Rootfs.isNullDevice("/dev/zero"), "another character device");
        Path file = Files.createFile(tmp.resolve("null"));
        assertFalse(Rootfs.isNullDevice(file.toString()), "a regular file");
        Path link = Files.createSymbolicLink(tmp.resolve("link"), file);
        assertFalse(Rootfs.isNullDevice(link.toString()), "a symlink to a regular file");
    }
}
