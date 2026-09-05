package com.ternbusty.takoyaki.apparmor

import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.mockStatic
import java.nio.file.Files
import java.nio.file.Path

class AppArmorTest {

    @Test
    fun nullProfileIsNoOp() {
        mockStatic(Files::class.java).use { fm ->
            AppArmor.apply(null)
            fm.verifyNoInteractions()
        }
    }

    @Test
    fun emptyProfileIsNoOp() {
        mockStatic(Files::class.java).use { fm ->
            AppArmor.apply("")
            fm.verifyNoInteractions()
        }
    }

    @Test
    fun unconfinedSentinelIsNoOp() {
        // OCI spec: an apparmorProfile of "unconfined" means *do nothing*.
        // We must NOT treat it as a real profile name and try to load it.
        mockStatic(Files::class.java).use { fm ->
            AppArmor.apply("unconfined")
            fm.verifyNoInteractions()
        }
    }

    @Test
    fun neitherAttrPathExistsLogsWarnButDoesNotThrow() {
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(false)
            assertDoesNotThrow { AppArmor.apply("test-profile") }
            // Both candidate paths must have been probed.
            fm.verify { Files.exists(eq(Path.of("/proc/self/attr/apparmor/exec"))) }
            fm.verify { Files.exists(eq(Path.of("/proc/self/attr/exec"))) }
        }
    }
}
