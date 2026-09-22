package com.ternbusty.takoyaki.apparmor;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AppArmorTest {

    @Test
    void nullProfileIsNoOp() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            AppArmor.apply(null);
            fm.verifyNoInteractions();
        }
    }

    @Test
    void emptyProfileIsNoOp() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            AppArmor.apply("");
            fm.verifyNoInteractions();
        }
    }

    @Test
    void unconfinedSentinelIsNoOp() {
        // OCI spec: an apparmorProfile of "unconfined" means *do nothing*.
        // We must NOT treat it as a real profile name and try to load it.
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            AppArmor.apply("unconfined");
            fm.verifyNoInteractions();
        }
    }

    @Test
    void neitherAttrPathExistsLogsWarnButDoesNotThrow() {
        try (MockedStatic<Files> fm = mockStatic(Files.class)) {
            fm.when(() -> Files.exists(any(Path.class))).thenReturn(false);
            assertDoesNotThrow(() -> AppArmor.apply("test-profile"));
            // Both candidate paths must have been probed.
            fm.verify(() -> Files.exists(eq(Path.of("/proc/thread-self/attr/apparmor/exec"))));
            fm.verify(() -> Files.exists(eq(Path.of("/proc/thread-self/attr/exec"))));
        }
    }
}
