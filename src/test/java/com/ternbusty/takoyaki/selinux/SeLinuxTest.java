package com.ternbusty.takoyaki.selinux;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SeLinuxTest {

    @Test
    void nullLabelIsNoOp() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            SeLinux.apply(null);
            fm.verifyNoInteractions();
        }
    }

    @Test
    void emptyLabelIsNoOp() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            SeLinux.apply("");
            fm.verifyNoInteractions();
        }
    }

    @Test
    void selinuxNotMountedIsSkippedSilently() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(false);
            SeLinux.apply("system_u:system_r:container_t:s0");
            // Skip path: nothing should have been written.
            fm.verify(() -> Files.writeString(any(Path.class), anyString()), never());
        }
    }

    @Test
    void labelIsWrittenToAttrExecWhenSelinuxIsMounted() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(eq(Path.of("/sys/fs/selinux")))).thenReturn(true);
            fm.when(() -> Files.writeString(any(Path.class), anyString()))
                    .thenReturn(Path.of("/dev/null"));

            SeLinux.apply("system_u:system_r:container_t:s0");

            fm.verify(() -> Files.writeString(
                    eq(Path.of("/proc/thread-self/attr/exec")),
                    eq("system_u:system_r:container_t:s0")));
        }
    }

    @Test
    void writeFailureIsLoggedNotPropagated() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(true);
            fm.when(() -> Files.writeString(any(Path.class), anyString()))
                    .thenThrow(new java.io.IOException("EPERM"));
            assertDoesNotThrow(() -> SeLinux.apply("label"));
        }
    }

    @Test
    void applyKeyCreateNullIsNoOp() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            SeLinux.applyKeyCreate(null);
            SeLinux.applyKeyCreate("");
            fm.verifyNoInteractions();
        }
    }
}
