package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls.MountCall;
import com.ternbusty.takoyaki.syscall.SyscallHost;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drive Rootfs.applyOciMounts directly via the youki-style RecordingSyscalls
 * fake — previously impossible because the method was private and reached
 * Libc.mount statics. With the Syscalls trait migration done, every mount(2)
 * the loop issues now becomes a list entry we can pin in order.
 */
class RootfsApplyOciMountsTest {

    private static Spec.Mount mount(String dest, String src, String type, List<String> options) {
        Spec.Mount m = new Spec.Mount();
        m.destination = dest;
        m.source = src;
        m.type = type;
        m.options = options;
        return m;
    }

    @Test
    void wellKnownDestinationsAreSkipped(@TempDir Path tmp) {
        // /proc, /dev, /sys, /dev/shm, /dev/pts, /dev/mqueue, /sys/fs/cgroup
        // are handled by the dedicated paths in Rootfs.prepare BEFORE the
        // generic loop runs. The generic loop MUST skip them or it would
        // double-mount and the second call would error in mysterious ways.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/proc",          "proc",   "proc",   null),
                    mount("/dev",           "tmpfs",  "tmpfs",  null),
                    mount("/sys",           "sysfs",  "sysfs",  null),
                    mount("/dev/shm",       "shm",    "tmpfs",  null),
                    mount("/dev/pts",       "devpts", "devpts", null),
                    mount("/dev/mqueue",    "mqueue", "mqueue", null),
                    mount("/sys/fs/cgroup", "cgroup", "cgroup2", null)
            ), Map.of());
        }
        assertTrue(rec.mountCalls().isEmpty(),
                "the well-known mount points are skipped by applyOciMounts");
    }

    @Test
    void nullDestinationIsSkippedNotCrashed(@TempDir Path tmp) {
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        Spec.Mount m = new Spec.Mount(); // destination = null
        try (var s = SyscallHost.install(rec)) {
            assertDoesNotThrow(() -> Rootfs.applyOciMounts(tmp.toString(),
                    List.of(m), Map.of()));
        }
        assertTrue(rec.mountCalls().isEmpty());
    }

    @Test
    void tmpfsMountIssuesOneCallWithTypeAndData(@TempDir Path tmp) {
        // Typical /tmp tmpfs in the spec: type=tmpfs, options=["nosuid","mode=755"].
        // Expect ONE mount call: source=tmpfs, target=<rootfs>/tmp, type=tmpfs,
        // flags=MS_NOSUID, data="mode=755". No remount (no bind), no propagation.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/tmp", "tmpfs", "tmpfs", List.of("nosuid", "mode=755"))
            ), Map.of());
        }

        assertEquals(1, rec.mountCalls().size());
        MountCall c = rec.mountCalls().get(0);
        assertEquals("tmpfs", c.source());
        assertEquals(tmp.toString() + "/tmp", c.target());
        assertEquals("tmpfs", c.fstype());
        assertEquals(Constants.MS_NOSUID, c.flags());
        assertEquals("mode=755", c.data());
    }

    @Test
    void bindMountPassesNullTypeNotTheSpecType(@TempDir Path tmp) {
        // The kernel rejects mount(MS_BIND) if fstype is non-null. The OCI
        // spec lets users set type="none" for binds; we must override it to
        // null on the actual syscall.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/data", "/host/data", "none", List.of("bind"))
            ), Map.of());
        }
        assertEquals(1, rec.mountCalls().size());
        assertNull(rec.mountCalls().get(0).fstype(),
                "bind mounts MUST pass NULL fstype to mount(2)");
        assertEquals("/host/data", rec.mountCalls().get(0).source());
        assertEquals(Constants.MS_BIND, rec.mountCalls().get(0).flags());
    }

    @Test
    void bindWithReadOnlyTriggersSecondRemountCallWithMsRemount(@TempDir Path tmp) {
        // Critical kernel contract: MS_RDONLY on a fresh bind is silently
        // dropped. To actually enforce read-only on a bind, we MUST issue a
        // second mount with MS_BIND|MS_REMOUNT|MS_RDONLY. Same for nosuid,
        // nodev, noexec, noatime, etc.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/etc/ro", "/host/etc", null, List.of("bind", "ro"))
            ), Map.of());
        }
        // Call 1: initial bind. Call 2: remount with MS_RDONLY.
        assertEquals(2, rec.mountCalls().size());
        // First: regular bind, MS_BIND|MS_RDONLY (RDONLY ignored by kernel
        // but we still pass it; this is faithful to spec semantics).
        assertEquals(Constants.MS_BIND | Constants.MS_RDONLY,
                rec.mountCalls().get(0).flags());
        // Second: MS_BIND|MS_REMOUNT|MS_RDONLY targets the SAME target with
        // null source and null type.
        long expected = Constants.MS_BIND | Constants.MS_REMOUNT | Constants.MS_RDONLY;
        assertEquals(expected, rec.mountCalls().get(1).flags());
        assertNull(rec.mountCalls().get(1).source());
        assertNull(rec.mountCalls().get(1).fstype());
        assertEquals(tmp.toString() + "/etc/ro", rec.mountCalls().get(1).target());
    }

    @Test
    void bindWithoutAccessFlagsDoesNotIssueExtraRemount(@TempDir Path tmp) {
        // Bind WITHOUT ro/nosuid/nodev/noexec must NOT trigger a remount call.
        // (Otherwise we'd waste a syscall and break some real-world mounts
        // that don't expect MS_REMOUNT.)
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/data", "/host/data", null, List.of("bind"))
            ), Map.of());
        }
        assertEquals(1, rec.mountCalls().size(),
                "plain bind must not be remounted");
    }

    @Test
    void perMountPropagationGoesInASeparateThirdCall(@TempDir Path tmp) {
        // Propagation flag (MS_PRIVATE / MS_SHARED / ...) MUST go in its own
        // mount(2) call, NEVER mixed with regular flags. Kernel returns EINVAL
        // if you mix them. This test pins both the "second call is the
        // propagation call" and the "regular flags stayed in call 1" contracts.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/data", "tmpfs", "tmpfs",
                            List.of("nosuid", "rprivate"))
            ), Map.of());
        }
        assertEquals(2, rec.mountCalls().size());
        // Call 1: tmpfs with regular MS_NOSUID, NO MS_PRIVATE bit.
        assertEquals(Constants.MS_NOSUID, rec.mountCalls().get(0).flags());
        // Call 2: propagation-only.
        assertEquals(Constants.MS_PRIVATE | Constants.MS_REC,
                rec.mountCalls().get(1).flags());
        assertNull(rec.mountCalls().get(1).source());
        assertNull(rec.mountCalls().get(1).fstype());
    }

    @Test
    void bindWithRoAndPropagationFiresAllThreeCallsInOrder(@TempDir Path tmp) {
        // The full sequence: initial bind -> ro remount -> propagation set.
        // We're pinning the ORDER because each kernel call has preconditions
        // (remount must come after bind, propagation must come last).
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/etc/ro", "/host/etc", null,
                            List.of("bind", "ro", "private"))
            ), Map.of());
        }
        assertEquals(3, rec.mountCalls().size());
        // Call 1: initial bind, source != null.
        assertEquals("/host/etc", rec.mountCalls().get(0).source());
        assertEquals(Constants.MS_BIND | Constants.MS_RDONLY,
                rec.mountCalls().get(0).flags());
        // Call 2: bind+remount+ro.
        assertEquals(Constants.MS_BIND | Constants.MS_REMOUNT | Constants.MS_RDONLY,
                rec.mountCalls().get(1).flags());
        // Call 3: propagation-only.
        assertEquals(Constants.MS_PRIVATE, rec.mountCalls().get(2).flags());
    }

    @Test
    void initialMountFailureSkipsBothRemountAndPropagation(@TempDir Path tmp) {
        // If the very first mount fails, the test must NOT issue the remount
        // and propagation calls — they'd target a nonexistent mount and
        // pollute the kernel-side journalctl.
        RecordingSyscalls rec = new RecordingSyscalls()
                .stubMountReturn(-1)
                .stubErrno(13 /* EACCES */);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/etc/ro", "/host/etc", null,
                            List.of("bind", "ro", "private"))
            ), Map.of());
        }
        assertEquals(1, rec.mountCalls().size(),
                "remount + propagation must not run when the initial mount failed");
    }

    @Test
    void multipleMountsAreProcessedInOrder(@TempDir Path tmp) {
        // A typical bundle has half a dozen mounts. They must execute in
        // the order they appear in spec.mounts — kernel mount propagation
        // depends on parent-before-child ordering.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/tmp",   "tmpfs",   "tmpfs", List.of("nosuid")),
                    mount("/run",   "tmpfs",   "tmpfs", List.of("nosuid", "mode=755")),
                    mount("/data",  "/host/d", null,    List.of("bind"))
            ), Map.of());
        }

        List<MountCall> calls = rec.mountCalls();
        assertEquals(3, calls.size());
        assertEquals(tmp.toString() + "/tmp",  calls.get(0).target());
        assertEquals(tmp.toString() + "/run",  calls.get(1).target());
        assertEquals(tmp.toString() + "/data", calls.get(2).target());
    }

    @Test
    void nosuidNodevNoexecAllPropagateToRemountFlags(@TempDir Path tmp) {
        // Lockdown bind recipe: bind + ro + nosuid + nodev + noexec. The
        // remount must include ALL four access-restricting bits, not just RDONLY.
        RecordingSyscalls rec = new RecordingSyscalls().stubMountReturn(0);
        try (var s = SyscallHost.install(rec)) {
            Rootfs.applyOciMounts(tmp.toString(), List.of(
                    mount("/data", "/host", null,
                            List.of("bind", "ro", "nosuid", "nodev", "noexec"))
            ), Map.of());
        }
        assertEquals(2, rec.mountCalls().size());
        long expected = Constants.MS_BIND | Constants.MS_REMOUNT
                | Constants.MS_RDONLY | Constants.MS_NOSUID
                | Constants.MS_NODEV  | Constants.MS_NOEXEC;
        assertEquals(expected, rec.mountCalls().get(1).flags());
    }
}
