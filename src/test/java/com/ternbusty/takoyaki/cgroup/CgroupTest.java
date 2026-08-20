package com.ternbusty.takoyaki.cgroup;

import com.ternbusty.takoyaki.spec.Spec;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CgroupTest {

    private static Spec.LinuxResources resources() {
        return new Spec.LinuxResources();
    }

    @Test
    void nullCgroupPathIsNoOp() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            Cgroup.setup(123, null, null);
            fm.verifyNoInteractions();
        }
    }

    @Test
    void leadingSlashIsStrippedBeforeResolving() {
        // We accept both "/takoyaki-x" and "takoyaki-x" from the spec. The
        // resulting cgroup path must be /sys/fs/cgroup/takoyaki-x either way.
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.createDirectories(any())).thenReturn(null);
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            fm.when(() -> Files.readString(any())).thenReturn("");

            Cgroup.setup(123, "/takoyaki-x", null);
            fm.verify(() -> Files.createDirectories(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-x"))));
            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-x/cgroup.procs")),
                    eq("123")));
        }
    }

    @Test
    void memoryLimitWritesMemoryMax() {
        // Confirm spec.linux.resources.memory.limit lands at memory.max with
        // the exact value (or "max" sentinel for -1).
        Spec.LinuxResources r = resources();
        r.memory = new Spec.LinuxMemory();
        r.memory.limit = 67108864L; // 64 MiB

        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.createDirectories(any())).thenReturn(null);
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            fm.when(() -> Files.readString(any())).thenReturn("");
            Spec.Linux linux = new Spec.Linux();
            linux.resources = r;
            Cgroup.setup(123, "/takoyaki-mem", linux);

            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-mem/memory.max")),
                    eq("67108864")));
        }
    }

    @Test
    void memoryMinusOneLimitWritesMaxSentinel() {
        Spec.LinuxResources r = resources();
        r.memory = new Spec.LinuxMemory();
        r.memory.limit = -1L;

        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.createDirectories(any())).thenReturn(null);
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            fm.when(() -> Files.readString(any())).thenReturn("");
            Spec.Linux linux = new Spec.Linux();
            linux.resources = r;
            Cgroup.setup(123, "/takoyaki-mem", linux);

            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-mem/memory.max")),
                    eq("max")));
        }
    }

    @Test
    void cpuCpusetIsApplied() {
        Spec.LinuxResources r = resources();
        r.cpu = new Spec.LinuxCpu();
        r.cpu.cpus = "0-1";

        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.createDirectories(any())).thenReturn(null);
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            fm.when(() -> Files.readString(any())).thenReturn("");
            Spec.Linux linux = new Spec.Linux();
            linux.resources = r;
            Cgroup.setup(123, "/takoyaki-cpu", linux);

            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-cpu/cpuset.cpus")),
                    eq("0-1")));
        }
    }

    @Test
    void cpuQuotaAndPeriodAreCombinedIntoCpuMax() {
        // cgroup v2 writes both as one string "quota period".
        Spec.LinuxResources r = resources();
        r.cpu = new Spec.LinuxCpu();
        r.cpu.quota = 50000L;
        r.cpu.period = 100000L;

        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.createDirectories(any())).thenReturn(null);
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            fm.when(() -> Files.readString(any())).thenReturn("");
            Spec.Linux linux = new Spec.Linux();
            linux.resources = r;
            Cgroup.setup(123, "/takoyaki-q", linux);

            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-q/cpu.max")),
                    eq("50000 100000")));
        }
    }

    @Test
    void pidsLimitIsDeferredDuringSetup() {
        // pids.max is deferred during setup() so the GraalVM init process
        // can create threads. applyDeferredPids() writes it after INIT_READY.
        Spec.LinuxResources r = resources();
        r.pids = new Spec.LinuxPids();
        r.pids.limit = 100;

        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.createDirectories(any())).thenReturn(null);
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            fm.when(() -> Files.readString(any())).thenReturn("");
            Spec.Linux linux = new Spec.Linux();
            linux.resources = r;
            Cgroup.setup(123, "/takoyaki-p", linux);

            // pids.max must NOT be written during setup.
            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-p/pids.max")),
                    anyString()), never());
        }
    }

    @Test
    void applyDeferredPidsWritesPidsMax() {
        Spec.LinuxResources r = resources();
        r.pids = new Spec.LinuxPids();
        r.pids.limit = 100;

        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            Cgroup.applyDeferredPids("/takoyaki-p", r);

            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/takoyaki-p/pids.max")),
                    eq("100")));
        }
    }

    @Test
    void enableControllersWalksParentChainTowardsRoot() {
        // For a nested cgroup like /takoyaki/sub the runtime must "+memory"
        // (etc.) in EACH ancestor's cgroup.subtree_control. Verify that
        // subtree_control writes hit at least the root.
        Spec.LinuxResources r = resources();
        r.memory = new Spec.LinuxMemory();
        r.memory.limit = 4096L;

        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.createDirectories(any())).thenReturn(null);
            fm.when(() -> Files.writeString(any(), anyString())).thenReturn(Path.of("/dev/null"));
            fm.when(() -> Files.readString(any())).thenReturn("");
            Spec.Linux linux = new Spec.Linux();
            linux.resources = r;
            Cgroup.setup(123, "/takoyaki/sub", linux);

            // The root cgroup must get a "+memory" write.
            fm.verify(() -> Files.writeString(
                    eq(Path.of("/sys/fs/cgroup/cgroup.subtree_control")),
                    eq("+memory")));
        }
    }

    @Test
    void cleanupRemovesDirectoryWhenItExists() {
        // The cleanup path is: write '1' to cgroup.kill -> retry rmdir until
        // it succeeds (or the deadline). On the happy path Files.delete
        // succeeds on the first attempt.
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            Path cgDir = Path.of("/sys/fs/cgroup/takoyaki-x");
            fm.when(() -> Files.exists(eq(cgDir))).thenReturn(true);
            fm.when(() -> Files.writeString(any(Path.class), anyString()))
                    .thenReturn(cgDir);
            fm.when(() -> Files.readString(any())).thenReturn("");
            // Files.delete returns void; the default (no stub) is to do nothing
            // and return successfully, which matches the happy path.

            Cgroup.cleanup("/takoyaki-x");

            fm.verify(() -> Files.writeString(
                    eq(cgDir.resolve("cgroup.kill")), eq("1")));
            fm.verify(() -> Files.delete(eq(cgDir)));
        }
    }

    @Test
    void cleanupSkipsEverythingWhenDirectoryDoesNotExist() {
        // No directory -> nothing to kill, nothing to poll, nothing to delete.
        // (Early return short-circuits the cgroup.kill write too.)
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any())).thenReturn(false);
            Cgroup.cleanup("/takoyaki-x");
            fm.verify(() -> Files.delete(any()), never());
            fm.verify(() -> Files.writeString(any(Path.class), anyString()), never());
        }
    }

    @Test
    void cleanupNullIsNoOp() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            Cgroup.cleanup(null);
            fm.verifyNoInteractions();
        }
    }
}
