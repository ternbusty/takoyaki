package com.ternbusty.takoyaki.rootfs

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertEquals

/**
 * makedev() encodes (major, minor) into the glibc dev_t layout the kernel expects
 * in mknod(2). Get this wrong and /dev/null lands on the wrong inode and every
 * read() inside the container starts returning EIO.
 *
 * Layout (glibc):
 *   bits 63..32  = upper 20 bits of major   (major & 0xfffff000) << 32
 *   bits 19..8   = lower 12 bits of major   (major & 0x00000fff) << 8
 *   bits 31..20  = upper 24 bits of minor   (minor & 0xffffff00) << 12
 *   bits  7..0   = lower 8 bits of minor    (minor & 0x000000ff)
 */
class DevicesMakedevTest {

    @Test
    fun nullDeviceIsAllZeros() {
        // (0, 0) is the canonical "no device" sentinel. Must round-trip to 0.
        assertEquals(0L, Devices.makedev(0L, 0L))
    }

    @Test
    fun smallMajorAndMinorPackIntoLowBits() {
        // /dev/null is (1, 3). All bits fit in low halves so we can compute by hand:
        //   major=1 -> bit 8  -> 0x100
        //   minor=3 -> bit 0  -> 0x003
        assertEquals(0x103L, Devices.makedev(1L, 3L))
    }

    @Test
    fun devZeroIsExpectedEncoding() {
        // /dev/zero is (1, 5). Sanity check a second well-known device.
        assertEquals(0x105L, Devices.makedev(1L, 5L))
    }

    @Test
    fun minorTopByteShiftsTo20() {
        // Take minor=0xFF00 (high byte set, low byte zero). It should land in
        // bits 27..20 via the << 12 shift: 0xFF00 << 12 = 0xFF00000.
        val encoded = Devices.makedev(0L, 0xFF00L)
        assertEquals(0xFF00000L, encoded)
    }

    @Test
    fun majorTop20BitsShiftPast32() {
        // Big bus major (> 4095) exercises the upper-half path. Pick 0x1000
        // (= 4096), which has bit 12 set, falling into the (major & 0xfffff000) << 32
        // arm. Expected encoding: 0x1000 << 32 = 0x1000_00000000.
        val encoded = Devices.makedev(0x1000L, 0L)
        assertEquals(0x1000_00000000L, encoded)
    }

    @Test
    fun disjointMajorAndMinorSlotsDoNotOverlap() {
        // Critical contract: major-bits and minor-bits live in non-overlapping
        // slots. Encoding (major, minor) = encoding(major, 0) | encoding(0, minor).
        val a = Devices.makedev(123L, 0L)
        val b = Devices.makedev(0L, 456L)
        val both = Devices.makedev(123L, 456L)
        assertEquals(a or b, both)
        assertEquals(0L, a and b, "major slot and minor slot must not overlap")
    }
}
