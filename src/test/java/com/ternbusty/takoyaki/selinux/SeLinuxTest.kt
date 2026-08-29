package com.ternbusty.takoyaki.selinux

import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.mockStatic
import org.mockito.Mockito.never
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

class SeLinuxTest {

    @Test
    fun nullLabelIsNoOp() {
        mockStatic(Files::class.java).use { fm ->
            SeLinux.apply(null)
            fm.verifyNoInteractions()
        }
    }

    @Test
    fun emptyLabelIsNoOp() {
        mockStatic(Files::class.java).use { fm ->
            SeLinux.apply("")
            fm.verifyNoInteractions()
        }
    }

    @Test
    fun selinuxNotMountedIsSkippedSilently() {
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(false)
            SeLinux.apply("system_u:system_r:container_t:s0")
            // Skip path: nothing should have been written.
            fm.verify({ Files.writeString(any(Path::class.java), anyString()) }, never())
        }
    }

    @Test
    fun labelIsWrittenToAttrExecWhenSelinuxIsMounted() {
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(eq(Path.of("/sys/fs/selinux"))) }.thenReturn(true)
            fm.`when`<Path> { Files.writeString(any(Path::class.java), anyString()) }
                .thenReturn(Path.of("/dev/null"))

            SeLinux.apply("system_u:system_r:container_t:s0")

            fm.verify {
                Files.writeString(
                    eq(Path.of("/proc/self/attr/exec")),
                    eq("system_u:system_r:container_t:s0")
                )
            }
        }
    }

    @Test
    fun writeFailureIsLoggedNotPropagated() {
        mockStatic(Files::class.java).use { fm ->
            fm.`when`<Boolean> { Files.exists(any(Path::class.java)) }.thenReturn(true)
            fm.`when`<Path> { Files.writeString(any(Path::class.java), anyString()) }
                .thenThrow(IOException("EPERM"))
            assertDoesNotThrow { SeLinux.apply("label") }
        }
    }

    @Test
    fun applyKeyCreateNullIsNoOp() {
        mockStatic(Files::class.java).use { fm ->
            SeLinux.applyKeyCreate(null)
            SeLinux.applyKeyCreate("")
            fm.verifyNoInteractions()
        }
    }
}
