package com.ternbusty.takoyaki.selinux;

import com.ternbusty.takoyaki.syscall.ProcFs;
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
        try (MockedStatic<Files> fm = mockStatic(Files.class);
             MockedStatic<ProcFs> pm = mockStatic(ProcFs.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(false);
            SeLinux.apply("system_u:system_r:container_t:s0");
            // Skip path: nothing should have been written.
            pm.verifyNoInteractions();
        }
    }

    @Test
    void labelIsWrittenToAttrExecWhenSelinuxIsMounted() {
        try (MockedStatic<Files> fm = mockStatic(Files.class);
             MockedStatic<ProcFs> pm = mockStatic(ProcFs.class)) {
            fm.when(() -> Files.exists(eq(Path.of("/sys/fs/selinux")))).thenReturn(true);

            SeLinux.apply("system_u:system_r:container_t:s0");

            pm.verify(() -> ProcFs.write(
                    eq("thread-self/attr/exec"),
                    eq("system_u:system_r:container_t:s0")));
        }
    }

    @Test
    void writeFailureIsLoggedNotPropagated() {
        try (MockedStatic<Files> fm = mockStatic(Files.class);
             MockedStatic<ProcFs> pm = mockStatic(ProcFs.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(true);
            pm.when(() -> ProcFs.write(anyString(), anyString()))
                    .thenThrow(new java.io.IOException("EPERM"));
            assertDoesNotThrow(() -> SeLinux.apply("label"));
        }
    }

    @Test
    void applyKeyCreateNullIsNoOp() {
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            SeLinux.applyKeyCreate(null);
            SeLinux.applyKeyCreate("");
            fm.verifyNoInteractions();
        }
    }
}
