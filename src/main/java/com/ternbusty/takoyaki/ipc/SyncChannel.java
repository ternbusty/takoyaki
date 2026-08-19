package com.ternbusty.takoyaki.ipc;

import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.lang.foreign.Arena;

public final class SyncChannel {
    public static final int MSG_INIT_READY = 0x50;
    public static final int MSG_USERMAP_PLS = 0x40;
    public static final int MSG_USERMAP_ACK = 0x41;
    public static final int MSG_CGROUP_ACK  = 0x42;

    private SyncChannel() {}

    public static int readInt32(int fd) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] b = new byte[4];
            long n = PosixIO.read(arena, fd, b);
            if (n != 4) {
                throw new RuntimeException("readInt32 got " + n + " bytes (errno=" +
                        Libc.errno() + " " + Libc.strerror(Libc.errno()) + ")");
            }
            return (b[0] & 0xff) | ((b[1] & 0xff) << 8) | ((b[2] & 0xff) << 16) | ((b[3] & 0xff) << 24);
        }
    }

    public static void writeInt32(int fd, int value) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] b = new byte[]{
                    (byte) (value & 0xff),
                    (byte) ((value >> 8) & 0xff),
                    (byte) ((value >> 16) & 0xff),
                    (byte) ((value >> 24) & 0xff),
            };
            long n = PosixIO.write(arena, fd, b);
            if (n != 4) throw new RuntimeException("writeInt32 wrote " + n + " bytes");
        }
    }

    /** Write a single sync byte. Used for lightweight ready signals. */
    public static void writeByte(int fd, byte value) {
        try (Arena arena = Arena.ofConfined()) {
            long n = PosixIO.write(arena, fd, new byte[]{value});
            if (n != 1) throw new RuntimeException("writeByte wrote " + n + " bytes");
        }
    }

    /** Read a single sync byte. Returns -1 on EOF. */
    public static int readByte(int fd) {
        try (Arena arena = Arena.ofConfined()) {
            byte[] b = new byte[1];
            long n = PosixIO.read(arena, fd, b);
            if (n <= 0) return -1;
            return b[0] & 0xff;
        }
    }
}
