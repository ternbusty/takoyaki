package com.ternbusty.takoyaki.ipc

import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import java.lang.foreign.Arena

object SyncChannel {
    const val MSG_INIT_READY = 0x50
    const val MSG_USERMAP_PLS = 0x40
    const val MSG_USERMAP_ACK = 0x41
    const val MSG_CGROUP_ACK = 0x42

    fun readInt32(fd: Int): Int {
        Arena.ofConfined().use { arena ->
            val b = ByteArray(4)
            val n = PosixIO.read(arena, fd, b)
            if (n != 4L) {
                throw RuntimeException(
                    "readInt32 got $n bytes (errno=${Libc.errno()} ${Libc.strerror(Libc.errno())})"
                )
            }
            return (b[0].toInt() and 0xff) or
                ((b[1].toInt() and 0xff) shl 8) or
                ((b[2].toInt() and 0xff) shl 16) or
                ((b[3].toInt() and 0xff) shl 24)
        }
    }

    fun writeInt32(fd: Int, value: Int) {
        Arena.ofConfined().use { arena ->
            val b = byteArrayOf(
                (value and 0xff).toByte(),
                ((value shr 8) and 0xff).toByte(),
                ((value shr 16) and 0xff).toByte(),
                ((value shr 24) and 0xff).toByte(),
            )
            val n = PosixIO.write(arena, fd, b)
            if (n != 4L) throw RuntimeException("writeInt32 wrote $n bytes")
        }
    }

    /** Write a single sync byte. Used for lightweight ready signals. */
    fun writeByte(fd: Int, value: Byte) {
        Arena.ofConfined().use { arena ->
            val n = PosixIO.write(arena, fd, byteArrayOf(value))
            if (n != 1L) throw RuntimeException("writeByte wrote $n bytes")
        }
    }

    /** Read a single sync byte. Returns -1 on EOF. */
    fun readByte(fd: Int): Int {
        Arena.ofConfined().use { arena ->
            val b = ByteArray(1)
            val n = PosixIO.read(arena, fd, b)
            if (n <= 0) return -1
            return b[0].toInt() and 0xff
        }
    }
}
