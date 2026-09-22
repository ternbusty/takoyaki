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
            assertDoesNotThrow(() -> SeLinux.apply("system_u:system_r:container_t:s0"));
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

    @Test
    void applyKeyCreateSkipsWhenFileNotExists() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(eq(Path.of("/proc/self/attr/keycreate")))).thenReturn(false);
            assertDoesNotThrow(() -> SeLinux.applyKeyCreate("system_u:system_r:container_t:s0"));
        }
    }
}
