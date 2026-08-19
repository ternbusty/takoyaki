package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.syscall.libc.LibcH;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * libc facade over the jextract-generated {@link LibcH} bindings. The public
 * surface is unchanged (Arena/String in, int/long out) so callers and the
 * {@code MockedStatic<Libc>} unit tests are unaffected; only the plumbing moved
 * from hand-written FFM downcalls to generated ones.
 *
 * Variadic functions (prctl, syscall, ioctl) are called through jextract's
 * {@code makeInvoker} factory with the fixed argument layouts takoyaki uses.
 */
public final class Libc {
    private Libc() {}

    private static final LibcH.prctl PRCTL =
            LibcH.prctl.makeInvoker(LibcH.C_LONG, LibcH.C_LONG, LibcH.C_LONG, LibcH.C_LONG);
    private static final LibcH.syscall SYSCALL =
            LibcH.syscall.makeInvoker(LibcH.C_LONG, LibcH.C_LONG, LibcH.C_LONG, LibcH.C_LONG, LibcH.C_LONG);
    private static final LibcH.ioctl IOCTL =
            LibcH.ioctl.makeInvoker(LibcH.C_POINTER);

    public static int unshare(int flags) {
        return LibcH.unshare(flags);
    }

    public static int setns(int fd, int nstype) {
        return LibcH.setns(fd, nstype);
    }

    public static int mount(Arena arena, String source, String target, String fstype, long flags, String data) {
        MemorySegment src = source == null ? MemorySegment.NULL : arena.allocateFrom(source);
        MemorySegment tgt = arena.allocateFrom(target);
        MemorySegment fs = fstype == null ? MemorySegment.NULL : arena.allocateFrom(fstype);
        MemorySegment dt = data == null ? MemorySegment.NULL : arena.allocateFrom(data);
        return LibcH.mount(src, tgt, fs, flags, dt);
    }

    public static int umount2(Arena arena, String target, int flags) {
        return LibcH.umount2(arena.allocateFrom(target), flags);
    }

    public static int pivotRoot(Arena arena, String newRoot, String putOld) {
        // glibc has no pivot_root wrapper (man 2 pivot_root), so go through the
        // raw syscall instead of relying on an undeclared libc symbol.
        MemorySegment nr = arena.allocateFrom(newRoot);
        MemorySegment po = arena.allocateFrom(putOld);
        return (int) syscall(Constants.NR_pivot_root, nr.address(), po.address(), 0, 0, 0);
    }

    public static int chdir(Arena arena, String path) {
        return LibcH.chdir(arena.allocateFrom(path));
    }

    public static int sethostname(Arena arena, String name) {
        return LibcH.sethostname(arena.allocateFrom(name), name.getBytes().length);
    }

    public static int setdomainname(Arena arena, String name) {
        return LibcH.setdomainname(arena.allocateFrom(name), name.getBytes().length);
    }

    public static int kill(int pid, int signal) {
        return LibcH.kill(pid, signal);
    }

    public static int prctl(int op, long a, long b, long c, long d) {
        return PRCTL.apply(op, a, b, c, d);
    }

    public static int umask(int mask) {
        return LibcH.umask(mask);
    }

    public static int getpid() {
        return LibcH.getpid();
    }

    public static int getppid() {
        return LibcH.getppid();
    }

    public static int errno() {
        return LibcH.__errno_location().reinterpret(4).get(ValueLayout.JAVA_INT, 0);
    }

    public static String strerror(int errnum) {
        return LibcH.strerror(errnum).reinterpret(Long.MAX_VALUE).getString(0);
    }

    public static int execvp(Arena arena, String file, String[] argv) {
        return LibcH.execvp(arena.allocateFrom(file), PosixIO.cStringArray(arena, argv));
    }

    public static int clearenv() {
        return LibcH.clearenv();
    }

    public static int setenv(Arena arena, String name, String value, boolean overwrite) {
        return LibcH.setenv(arena.allocateFrom(name), arena.allocateFrom(value), overwrite ? 1 : 0);
    }

    public static int setgroups(Arena arena, int[] gids) {
        MemorySegment seg = arena.allocate(ValueLayout.JAVA_INT, gids.length);
        for (int i = 0; i < gids.length; i++) seg.setAtIndex(ValueLayout.JAVA_INT, i, gids[i]);
        return LibcH.setgroups(gids.length, seg);
    }

    public static int prlimit64(Arena arena, int pid, int resource, long softCur, long hardMax) {
        MemorySegment newLim = arena.allocate(16);
        newLim.set(ValueLayout.JAVA_LONG, 0, softCur);
        newLim.set(ValueLayout.JAVA_LONG, 8, hardMax);
        return LibcH.prlimit64(pid, resource, newLim, MemorySegment.NULL);
    }

    public static long syscall(long nr, long a1, long a2, long a3, long a4, long a5) {
        return SYSCALL.apply(nr, a1, a2, a3, a4, a5);
    }

    public static int geteuid() {
        return LibcH.geteuid();
    }

    public static int getegid() {
        return LibcH.getegid();
    }

    public static int setresuid(int ruid, int euid, int suid) {
        return LibcH.setresuid(ruid, euid, suid);
    }

    public static int setresgid(int rgid, int egid, int sgid) {
        return LibcH.setresgid(rgid, egid, sgid);
    }

    public static int mknod(Arena arena, String path, int mode, long dev) {
        return LibcH.mknod(arena.allocateFrom(path), mode, dev);
    }

    public static int chown(Arena arena, String path, int owner, int group) {
        return LibcH.chown(arena.allocateFrom(path), owner, group);
    }

    public static int ioctl(int fd, long request, MemorySegment arg) {
        return IOCTL.apply(fd, request, arg);
    }

    public static int waitpid(int pid, MemorySegment status, int options) {
        return LibcH.waitpid(pid, status, options);
    }
}
