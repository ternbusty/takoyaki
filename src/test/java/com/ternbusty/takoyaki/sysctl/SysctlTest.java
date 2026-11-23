package com.ternbusty.takoyaki.sysctl;

import com.ternbusty.takoyaki.syscall.ProcFs;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SysctlTest {

    @Test
    void nullMapIsNoOp() {
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            Sysctl.apply(null);
            fm.verifyNoInteractions();
        }
    }

    @Test
    void emptyMapIsNoOp() {
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            Sysctl.apply(Map.of());
            fm.verifyNoInteractions();
        }
    }

    @Test
    void dotsInKeyAreTurnedIntoSlashes() {
        // OCI sysctl keys use dots (net.ipv4.ip_forward) but the kernel's
        // virtual files use slashes (/proc/sys/net/ipv4/ip_forward, written through
        // ProcFs, which takes the path relative to /proc). This
        // translation is the entire job of Sysctl.apply.
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {

            Sysctl.apply(Map.of("net.ipv4.ip_forward", "1"));

            fm.verify(() -> ProcFs.write(eq("sys/net/ipv4/ip_forward"), eq("1")));
        }
    }

    @Test
    void writeFailureIsLoggedNotPropagated() {
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            fm.when(() -> ProcFs.write(anyString(), anyString()))
                    .thenThrow(new IOException("EROFS"));

            // The runtime is supposed to warn and continue, not crash, when
            // a sysctl is denied (host kernel rejects, namespace forbids, …).
            assertDoesNotThrow(() -> Sysctl.apply(Map.of("kernel.hostname", "foo")));
        }
    }

    @Test
    void nonNamespacedKeysAreRejectedWithoutWriting() {
        // kernel.core_pattern, kernel.modprobe, vm.*, etc. are host-global.
        // A rootful container init still holds CAP_SYS_ADMIN in the initial
        // user namespace at this point, so a naive write would succeed and
        // mutate the host. The allowlist must refuse them.
        Map<String, String> in = new LinkedHashMap<>();
        in.put("kernel.core_pattern", "|/tmp/pwn.sh %P");
        in.put("kernel.modprobe",     "/tmp/pwn.sh");
        in.put("vm.swappiness",       "0");
        in.put("fs.file-max",         "999999");

        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            Sysctl.apply(in);
            fm.verify(() -> ProcFs.write(anyString(), anyString()), never());
        }
    }

    @Test
    void mixedGoodAndBadOnlyWritesTheGood() {
        Map<String, String> in = new LinkedHashMap<>();
        in.put("kernel.core_pattern",       "|/tmp/pwn.sh");   // rejected
        in.put("net.ipv4.ip_forward",       "1");              // allowed
        in.put("vm.swappiness",             "0");              // rejected
        in.put("fs.mqueue.msg_max",         "100");            // allowed

        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            Sysctl.apply(in);

            fm.verify(() -> ProcFs.write(eq("sys/net/ipv4/ip_forward"), eq("1")));
            fm.verify(() -> ProcFs.write(eq("sys/fs/mqueue/msg_max"), eq("100")));
            fm.verify(() -> ProcFs.write(eq("sys/kernel/core_pattern"), anyString()), never());
            fm.verify(() -> ProcFs.write(eq("sys/vm/swappiness"), anyString()), never());
        }
    }

    @Test
    void allEntriesAreAttemptedEvenIfOneFails() {
        // Use LinkedHashMap so we control ordering of the assertions below.
        Map<String, String> in = new LinkedHashMap<>();
        in.put("net.ipv4.bad_key",   "1");
        in.put("net.ipv4.good_key", "2");

        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            fm.when(() -> ProcFs.write(eq("sys/net/ipv4/bad_key"), anyString()))
                    .thenThrow(new IOException("EROFS"));
            
            Sysctl.apply(in);

            // Even though the first entry threw, the loop must have attempted
            // the second one.
            fm.verify(() -> ProcFs.write(eq("sys/net/ipv4/good_key"), eq("2")));
        }
    }
}
