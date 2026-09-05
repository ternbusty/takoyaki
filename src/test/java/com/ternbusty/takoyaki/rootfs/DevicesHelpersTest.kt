package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.syscall.Constants
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.attribute.PosixFilePermission
import java.util.EnumSet

/**
 * Pure helpers extracted out of Devices.create. typeBits maps the spec's
 * single-letter device type to the kernel's S_IF* bits; permsForMode does
 * the awkward "9 bits to PosixFilePermission set" translation that previously
 * lived as 9 inline if-statements.
 */
class DevicesHelpersTest {

    // ---- typeBits -----------------------------------------------------------

    @Test
    fun charDeviceMapsToSIfchr() {
        // "c" is the standard char device letter, used by /dev/null /dev/zero
        // /dev/random etc. Must produce S_IFCHR.
        assertEquals(Constants.S_IFCHR, Devices.typeBits("c"))
    }

    @Test
    fun unbufferedCharDeviceAlsoMapsToSIfchr() {
        // "u" is the OCI spec's "unbuffered char device" -- the kernel treats
        // it identically to "c" for mknod purposes. Tested separately to pin
        // the alias relationship.
        assertEquals(Constants.S_IFCHR, Devices.typeBits("u"))
    }

    @Test
    fun blockDeviceMapsToSIfblk() {
        assertEquals(Constants.S_IFBLK, Devices.typeBits("b"))
    }

    @Test
    fun fifoMapsToSIfifo() {
        assertEquals(Constants.S_IFIFO, Devices.typeBits("p"))
    }

    @Test
    fun unknownTypeReturnsZeroAsSkipSentinel() {
        // The caller treats 0 as "skip this device with a warning". A bug
        // that returned -1 or threw would crash init on a typo'd spec.
        assertEquals(0, Devices.typeBits(""))
        assertEquals(0, Devices.typeBits("socket"))
        assertEquals(0, Devices.typeBits("garbage"))
    }

    // ---- permsForMode -------------------------------------------------------

    @Test
    fun permsForMode0644IsOwnerRWAndOthersRead() {
        // Most common file mode. Sanity check it produces what Files API expects.
        val perms = Devices.permsForMode(420) // 0644 octal
        assertEquals(
            EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ,
                PosixFilePermission.OTHERS_READ
            ), perms
        )
    }

    @Test
    fun permsForMode0666IsAllRW() {
        // The default for /dev/null and /dev/zero per the OCI default-device list.
        val perms = Devices.permsForMode(438) // 0666 octal
        assertEquals(
            EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ,
                PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.OTHERS_READ,
                PosixFilePermission.OTHERS_WRITE
            ), perms
        )
    }

    @Test
    fun permsForMode0755IsExecBits() {
        val perms = Devices.permsForMode(493) // 0755 octal
        assertEquals(
            EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
                PosixFilePermission.GROUP_READ,
                PosixFilePermission.GROUP_EXECUTE,
                PosixFilePermission.OTHERS_READ,
                PosixFilePermission.OTHERS_EXECUTE
            ), perms
        )
    }

    @Test
    fun permsForMode0000IsEmpty() {
        // Edge case: mode=000 is a valid (if useless) permission. Must not
        // throw and must produce an empty set.
        assertTrue(Devices.permsForMode(0).isEmpty())
    }

    @Test
    fun permsForMode0777IsAll() {
        // All 9 bits set, all 9 PosixFilePermission values present.
        assertEquals(
            EnumSet.allOf(PosixFilePermission::class.java),
            Devices.permsForMode(511) // 0777 octal
        )
    }

    @Test
    fun permsForModeHighBitsAreIgnored() {
        // Caller masks with 0777 before calling, but defend in depth. The
        // sticky / setuid bits (0o4000, 0o2000, 0o1000) and the type bits
        // (S_IFCHR=0o20000 etc.) must not produce extra permissions.
        val lowOnly = Devices.permsForMode(438) // 0666 octal
        val withHighBits = Devices.permsForMode(65462) // 0177666 octal
        assertEquals(
            lowOnly, withHighBits,
            "permsForMode must only look at the bottom 9 bits"
        )
    }

    @Test
    fun permsForMode0240IsGroupWriteOwnerWriteOnly() {
        // Weird mode to make sure each bit lights up its own perm independently.
        // 0o240 = 010 100 000 = OWNER_WRITE, GROUP_READ.
        val perms = Devices.permsForMode(160) // 0240 octal
        assertEquals(
            EnumSet.of(
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ
            ), perms
        )
    }
}
