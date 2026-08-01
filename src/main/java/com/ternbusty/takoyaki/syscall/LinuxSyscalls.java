package com.ternbusty.takoyaki.syscall;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Real-kernel implementation of {@link Syscalls}.
 *
 * Just forwards to the existing {@link Libc} / {@link PosixIO} statics — those
 * stay in place during the migration so any code not yet ported keeps working.
 * Once every callsite goes through {@link Syscalls}, we can drop direct static
 * calls and inline the Panama FFM bits here.
 */
public final class LinuxSyscalls implements Syscalls {

    @Override
    public int mount(String source, String target, String fstype, long flags, String data) {
        try (Arena arena = Arena.ofConfined()) {
            return Libc.mount(arena, source, target, fstype, flags, data);
        }
    }

    @Override
    public int umount2(String target, int flags) {
        try (Arena arena = Arena.ofConfined()) {
            return Libc.umount2(arena, target, flags);
        }
    }

    @Override
    public int errno() {
        return Libc.errno();
    }

    @Override
    public String strerror(int errnum) {
        return Libc.strerror(errnum);
    }

    @Override
    public int kill(int pid, int sig) {
        return Libc.kill(pid, sig);
    }

    @Override
    public long syscall(long nr, long a1, long a2, long a3, long a4, long a5) {
        return Libc.syscall(nr, a1, a2, a3, a4, a5);
    }

    @Override
    public int prlimit64(int pid, int resource, long soft, long hard) {
        try (Arena arena = Arena.ofConfined()) {
            return Libc.prlimit64(arena, pid, resource, soft, hard);
        }
    }

    /** ifreq layout: name[16] + flags at offset 16. Buffer is 40 bytes total. */
    private static final int IFNAMSIZ = 16;
    private static final int IFREQ_SIZE = 40;

    @Override
    public int ifUp(String ifaceName) {
        try (Arena arena = Arena.ofConfined()) {
            int fd = PosixIO.socket(Constants.AF_INET, Constants.SOCK_DGRAM, 0);
            if (fd < 0) return -1;
            try {
                MemorySegment ifr = arena.allocate(IFREQ_SIZE, 8);
                byte[] name = (ifaceName + "\0").getBytes();
                for (int i = 0; i < name.length && i < IFNAMSIZ; i++) {
                    ifr.set(ValueLayout.JAVA_BYTE, i, name[i]);
                }
                if (Libc.ioctl(fd, Constants.SIOCGIFFLAGS, ifr) != 0) return -1;
                short flags = ifr.get(ValueLayout.JAVA_SHORT, IFNAMSIZ);
                flags |= (short) Constants.IFF_UP;
                ifr.set(ValueLayout.JAVA_SHORT, IFNAMSIZ, flags);
                if (Libc.ioctl(fd, Constants.SIOCSIFFLAGS, ifr) != 0) return -1;
                return 0;
            } finally {
                PosixIO.close(fd);
            }
        }
    }


    @Override
    public long keyctlJoinSessionKeyring(String name) {
        long nr = Constants.NR_keyctl;
        long arg = 0L;
        Arena arena = null;
        try {
            if (name != null) {
                arena = Arena.ofConfined();
                arg = arena.allocateFrom(name).address();
            }
            return Libc.syscall(nr, (long) Constants.KEYCTL_JOIN_SESSION_KEYRING,
                    arg, 0, 0, 0);
        } finally {
            if (arena != null) arena.close();
        }
    }

    @Override
    public int mknod(String path, int mode, long dev) {
        try (Arena arena = Arena.ofConfined()) {
            return Libc.mknod(arena, path, mode, dev);
        }
    }

    @Override
    public int access(String path, int mode) {
        try (Arena arena = Arena.ofConfined()) {
            return PosixIO.access(arena, path, mode);
        }
    }
}
