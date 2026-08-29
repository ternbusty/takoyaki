package com.ternbusty.takoyaki.ipc

import com.ternbusty.takoyaki.syscall.PosixIO
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

/**
 * SyncChannel is the framing layer between Stage-1 and Stage-2 of the runtime.
 * The wire format is a little-endian 4-byte integer per message. If endianness
 * or framing slips, every Create-time handshake (USERMAP_PLS/ACK, INIT_READY)
 * goes wrong and the container hangs forever.
 */
class SyncChannelTest {

    @Test
    fun messageSentinelsHaveStableValues() {
        // Pinning these values because they're a wire contract — Stage-1 and
        // Stage-2 are different processes, so the numbers MUST match across
        // runs and across builds.
        assertEquals(0x50, SyncChannel.MSG_INIT_READY)
        assertEquals(0x40, SyncChannel.MSG_USERMAP_PLS)
        assertEquals(0x41, SyncChannel.MSG_USERMAP_ACK)
    }

    @Test
    fun writeInt32EmitsLittleEndianBytes() {
        // 0x12345678 -> bytes 78 56 34 12 (LE), matching how InitProcess.c
        // reads them on the other end.
        mockkStatic(PosixIO::write)
        try {
            every { PosixIO.write(any(), any(), any()) } returns 4L

            SyncChannel.writeInt32(7, 0x12345678)

            // Match a byte[] whose contents are exactly 78 56 34 12.
            verify { PosixIO.write(any(), eq(7),
                match { b: ByteArray ->
                    b.size == 4
                        && (b[0].toInt() and 0xff) == 0x78
                        && (b[1].toInt() and 0xff) == 0x56
                        && (b[2].toInt() and 0xff) == 0x34
                        && (b[3].toInt() and 0xff) == 0x12
                }) }
        } finally {
            unmockkStatic(PosixIO::write)
        }
    }

    @Test
    fun writeInt32ForKnownSentinelsEmitsExpectedBytes() {
        // MSG_INIT_READY = 0x50 -> bytes 50 00 00 00 (LE).
        mockkStatic(PosixIO::write)
        try {
            every { PosixIO.write(any(), any(), any()) } returns 4L

            SyncChannel.writeInt32(3, SyncChannel.MSG_INIT_READY)

            verify { PosixIO.write(any(), eq(3),
                match { b: ByteArray ->
                    b.size == 4
                        && (b[0].toInt() and 0xff) == 0x50
                        && b[1].toInt() == 0 && b[2].toInt() == 0 && b[3].toInt() == 0
                }) }
        } finally {
            unmockkStatic(PosixIO::write)
        }
    }

    @Test
    fun writeInt32ShortWriteThrows() {
        // A short write (n != 4) MUST throw — Stage-2 would otherwise block
        // reading 4 bytes that will never arrive, deadlocking init.
        mockkStatic(PosixIO::write)
        try {
            every { PosixIO.write(any(), any(), any()) } returns 2L

            assertThrows(RuntimeException::class.java) {
                SyncChannel.writeInt32(3, 0)
            }
        } finally {
            unmockkStatic(PosixIO::write)
        }
    }

    @Test
    fun readInt32DecodesLittleEndianBytes() {
        // Inverse of writeInt32: bytes 78 56 34 12 on the wire -> 0x12345678.
        mockkStatic(PosixIO::read)
        try {
            every { PosixIO.read(any(), any(), any()) } answers {
                val buf = thirdArg<ByteArray>()
                buf[0] = 0x78.toByte()
                buf[1] = 0x56.toByte()
                buf[2] = 0x34.toByte()
                buf[3] = 0x12.toByte()
                4L
            }

            assertEquals(0x12345678, SyncChannel.readInt32(5))
        } finally {
            unmockkStatic(PosixIO::read)
        }
    }

    @Test
    fun readInt32HandlesAllZeroes() {
        // The wire-zero case must round-trip. (Used when sender wants to signal
        // a benign sentinel like "nothing".)
        mockkStatic(PosixIO::read)
        try {
            every { PosixIO.read(any(), any(), any()) } returns 4L
            assertEquals(0, SyncChannel.readInt32(5))
        } finally {
            unmockkStatic(PosixIO::read)
        }
    }

    @Test
    fun readInt32HandlesAllOnesAsExpectedSignedValue() {
        // 0xFF 0xFF 0xFF 0xFF must decode to -1 (the high bit propagates).
        // This is what kernel error returns look like when surfaced via the
        // channel.
        mockkStatic(PosixIO::read)
        try {
            every { PosixIO.read(any(), any(), any()) } answers {
                val buf = thirdArg<ByteArray>()
                buf[0] = 0xff.toByte()
                buf[1] = 0xff.toByte()
                buf[2] = 0xff.toByte()
                buf[3] = 0xff.toByte()
                4L
            }
            assertEquals(-1, SyncChannel.readInt32(5))
        } finally {
            unmockkStatic(PosixIO::read)
        }
    }

    @Test
    fun readInt32ShortReadThrows() {
        // A short read (peer closed the fd mid-frame) MUST surface as an
        // exception so the caller doesn't proceed with a half-read sentinel.
        mockkStatic(PosixIO::read)
        try {
            every { PosixIO.read(any(), any(), any()) } returns 2L

            assertThrows(RuntimeException::class.java) {
                SyncChannel.readInt32(5)
            }
        } finally {
            unmockkStatic(PosixIO::read)
        }
    }

    @Test
    fun writeThenReadRoundTrips() {
        // End-to-end: capture what writeInt32 hands to PosixIO, replay it
        // through readInt32. This is the "Stage-1 sends, Stage-2 receives"
        // contract in miniature.
        val wireBuf = arrayOfNulls<ByteArray>(1)

        mockkStatic(PosixIO::write, PosixIO::read)
        try {
            every { PosixIO.write(any(), any(), any()) } answers {
                val src = thirdArg<ByteArray>()
                wireBuf[0] = src.clone()
                src.size.toLong()
            }
            every { PosixIO.read(any(), any(), any()) } answers {
                val dst = thirdArg<ByteArray>()
                System.arraycopy(wireBuf[0]!!, 0, dst, 0, dst.size)
                dst.size.toLong()
            }

            val samples = intArrayOf(0, 1, 0x40, 0x41, 0x50, 0x12345678, -1, Int.MAX_VALUE)
            for (v in samples) {
                SyncChannel.writeInt32(3, v)
                assertEquals(v, SyncChannel.readInt32(3)) {
                    "round-trip failed for value 0x${Integer.toHexString(v)}"
                }
            }
        } finally {
            unmockkStatic(PosixIO::write, PosixIO::read)
        }
    }
}
