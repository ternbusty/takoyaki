package com.ternbusty.takoyaki.apparmor;

import com.ternbusty.takoyaki.syscall.ProcFs;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AppArmorTest {

    @Test
    void nullProfileIsNoOp() {
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            AppArmor.apply(null);
            fm.verifyNoInteractions();
        }
    }

    @Test
    void emptyProfileIsNoOp() {
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            AppArmor.apply("");
            fm.verifyNoInteractions();
        }
    }

    @Test
    void unconfinedSentinelIsNoOp() {
        // OCI spec: an apparmorProfile of "unconfined" means *do nothing*.
        // We must NOT treat it as a real profile name and try to load it.
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            AppArmor.apply("unconfined");
            fm.verifyNoInteractions();
        }
    }

    @Test
    void neitherAttrPathExistsLogsWarnButDoesNotThrow() {
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            fm.when(() -> ProcFs.exists(anyString())).thenReturn(false);
            assertDoesNotThrow(() -> AppArmor.apply("test-profile"));
            // Both candidate paths must have been probed.
            fm.verify(() -> ProcFs.exists(eq("thread-self/attr/apparmor/exec")));
            fm.verify(() -> ProcFs.exists(eq("thread-self/attr/exec")));
        }
    }

    @Test
    void profileIsStagedThroughTheNewerPathInOneWrite() {
        // The exec command goes to attr/apparmor/exec when it exists, through
        // ProcFs, so a file mounted over it cannot take the write.
        try (MockedStatic<ProcFs> fm = mockStatic(ProcFs.class)) {
            fm.when(() -> ProcFs.exists(anyString())).thenReturn(true);
            AppArmor.apply("test-profile");
            fm.verify(() -> ProcFs.write(eq("thread-self/attr/apparmor/exec"),
                    aryEq("exec test-profile".getBytes())));
            fm.verify(() -> ProcFs.write(eq("thread-self/attr/exec"), any(byte[].class)), never());
        }
    }
}
