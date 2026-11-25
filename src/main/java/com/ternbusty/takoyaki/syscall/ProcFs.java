package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.ffi.structs.open_how;
import com.ternbusty.takoyaki.ffi.structs.stat;
import com.ternbusty.takoyaki.ffi.structs.statfs;
import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Writes to procfs files that cannot be sent elsewhere.
 *
 * <p>The runtime writes to procfs inside the container's mount namespace
 * (attr/exec for the AppArmor and SELinux labels, attr/keycreate, /proc/sys
 * for sysctls, oom_score_adj), where the spec's mounts have been made. If one
 * of them puts another file over the target (another procfs file bind-mounted
 * over it, or something that is not procfs mounted on /proc), a write by path
 * goes to that file instead: runc's CVE-2025-52881 used this to write to
 * /proc/sys/kernel/core_pattern and the like, or to skip the LSM label. So
 * /proc is checked to be the root of a procfs, the file is opened from it
 * with openat2(RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH),
 * which fails on any mount or symlink on the way, and the opened file is
 * checked to be on procfs.
 *
 * <p>Paths are relative to /proc. A leading "self" or "thread-self" is
 * resolved here first, as those are the only symlinks on the way.
 *
 * <p>When a check finds something else in place of the file, an
 * {@link IllegalStateException} is thrown rather than an IOException, so it
 * fails the container instead of being taken for a missing file.
 *
 * <p>Without openat2 (kernel before 5.6) the file is opened by path and only
 * checked to be on procfs, which does not catch one procfs file mounted over
 * another.
 */
public final class ProcFs {
    private ProcFs() {}

    /** Inode number of the root of a procfs (PROC_ROOT_INO in fs/proc). */
    private static final long PROC_ROOT_INO = 1;
    private static final long RESOLVE = Constants.RESOLVE_NO_XDEV | Constants.RESOLVE_NO_SYMLINKS
            | Constants.RESOLVE_NO_MAGICLINKS | Constants.RESOLVE_BENEATH;

    /** Write {@code value} to the procfs file {@code path} in one write(2). */
    public static void write(String path, byte[] value) throws IOException {
        int fd = open(path, Constants.O_WRONLY | Constants.O_CLOEXEC);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocate(Math.max(1, value.length));
            MemorySegment.copy(value, 0, buf, ValueLayout.JAVA_BYTE, 0, value.length);
            long n = NativeH.write(fd, buf, value.length);
            if (n < 0) throw new IOException("write /proc/" + path + ": " + Libc.strerror(Libc.errno()));
            if (n != value.length) throw new IOException("short write to /proc/" + path);
        } finally {
            PosixIO.close(fd);
        }
    }

    /** As {@link #write(String, byte[])}, for text. */
    public static void write(String path, String value) throws IOException {
        write(path, value.getBytes());
    }

    /** Whether the procfs file {@code path} exists (and is procfs). */
    public static boolean exists(String path) {
        try {
            PosixIO.close(open(path, Constants.O_PATH | Constants.O_CLOEXEC));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Whether {@code path} (an absolute path, not one relative to /proc) is on procfs. */
    public static boolean isProcfs(String path) {
        int fd;
        try (Arena arena = Arena.ofConfined()) {
            fd = PosixIO.open(arena, path, Constants.O_PATH | Constants.O_CLOEXEC, 0);
        }
        if (fd < 0) return false;
        try {
            return isProcfs(fd);
        } catch (IOException e) {
            return false;
        } finally {
            PosixIO.close(fd);
        }
    }

    private static int open(String path, int flags) throws IOException {
        int root;
        try (Arena arena = Arena.ofConfined()) {
            root = PosixIO.open(arena, "/proc", Constants.O_PATH | Constants.O_DIRECTORY | Constants.O_CLOEXEC, 0);
        }
        if (root < 0) throw new IOException("open /proc: " + Libc.strerror(Libc.errno()));
        try {
            if (!isProcfs(root) || inode(root) != PROC_ROOT_INO) {
                throw new IllegalStateException("/proc is not the root of a procfs");
            }
            String rel = resolveSelf(root, path);
            int fd = openat2(root, rel, flags, RESOLVE);
            if (fd < 0 && Libc.errno() == Constants.ENOSYS) {
                try (Arena arena = Arena.ofConfined()) {
                    fd = PosixIO.open(arena, "/proc/" + rel, flags | Constants.O_NOFOLLOW, 0);
                }
            }
            if (fd < 0) {
                int err = Libc.errno();
                if (err == Constants.EXDEV || err == Constants.ELOOP) {
                    throw new IllegalStateException("/proc/" + path
                            + " has a mount or symlink on it (" + Libc.strerror(err) + ")");
                }
                throw new IOException("open /proc/" + path + ": " + Libc.strerror(err));
            }
            if (!isProcfs(fd)) {
                PosixIO.close(fd);
                throw new IllegalStateException("/proc/" + path + " is not on procfs");
            }
            return fd;
        } finally {
            PosixIO.close(root);
        }
    }

    /** Replace a leading "self" or "thread-self" with what it points to. */
    private static String resolveSelf(int root, String path) throws IOException {
        int slash = path.indexOf('/');
        String first = slash < 0 ? path : path.substring(0, slash);
        if (!first.equals("self") && !first.equals("thread-self")) return path;
        String target;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocate(256);
            long n = NativeH.readlinkat(root, arena.allocateFrom(first), buf, 255L);
            if (n < 0) throw new IOException("readlink /proc/" + first + ": " + Libc.strerror(Libc.errno()));
            byte[] b = new byte[(int) n];
            MemorySegment.copy(buf, ValueLayout.JAVA_BYTE, 0, b, 0, (int) n);
            target = new String(b);
        }
        return slash < 0 ? target : target + path.substring(slash);
    }

    private static boolean isProcfs(int fd) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment st = statfs.allocate(arena);
            if (NativeH.fstatfs(fd, st) != 0) {
                throw new IOException("fstatfs: " + Libc.strerror(Libc.errno()));
            }
            return statfs.f_type(st) == Constants.PROC_SUPER_MAGIC;
        }
    }

    private static long inode(int fd) throws IOException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment st = stat.allocate(arena);
            if (NativeH.fstat(fd, st) != 0) {
                throw new IOException("fstat: " + Libc.strerror(Libc.errno()));
            }
            return stat.st_ino(st);
        }
    }

    private static int openat2(int dirfd, String path, long flags, long resolve) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment how = open_how.allocate(arena);
            open_how.flags(how, flags);
            open_how.mode(how, 0);
            open_how.resolve(how, resolve);
            MemorySegment p = arena.allocateFrom(path);
            return (int) Libc.syscall(Constants.NR_openat2, dirfd, p.address(), how.address(),
                    open_how.sizeof(), 0);
        }
    }
}
