package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * libc facade over the jextract-generated {@link NativeH} bindings. The public
 * surface is unchanged (Arena/String in, int/long out) so callers and the
 * {@code MockedStatic<Libc>} unit tests are unaffected; only the plumbing moved
 * from hand-written FFM downcalls to generated ones.
 *
 * Variadic functions (prctl, syscall, ioctl) are called through jextract's
 * {@code makeInvoker} factory with the fixed argument layouts takoyaki uses.
 */
public final class Libc {
    private Libc() {}

    private static final NativeH.prctl PRCTL =
            NativeH.prctl.makeInvoker(NativeH.C_LONG, NativeH.C_LONG, NativeH.C_LONG, NativeH.C_LONG);
    private static final NativeH.syscall SYSCALL =
            NativeH.syscall.makeInvoker(NativeH.C_LONG, NativeH.C_LONG, NativeH.C_LONG, NativeH.C_LONG, NativeH.C_LONG);
    private static final NativeH.ioctl IOCTL =
            NativeH.ioctl.makeInvoker(NativeH.C_POINTER);

    public static int unshare(int flags) {
        return NativeH.unshare(flags);
    }

    public static int setns(int fd, int nstype) {
        return NativeH.setns(fd, nstype);
    }

    public static int mount(Arena arena, String source, String target, String fstype, long flags, String data) {
        MemorySegment src = source == null ? MemorySegment.NULL : arena.allocateFrom(source);
        MemorySegment tgt = arena.allocateFrom(target);
        MemorySegment fs = fstype == null ? MemorySegment.NULL : arena.allocateFrom(fstype);
        MemorySegment dt = data == null ? MemorySegment.NULL : arena.allocateFrom(data);
        return NativeH.mount(src, tgt, fs, flags, dt);
    }

    public static int umount2(Arena arena, String target, int flags) {
        return NativeH.umount2(arena.allocateFrom(target), flags);
    }

    public static int pivotRoot(Arena arena, String newRoot, String putOld) {
        // glibc has no pivot_root wrapper (man 2 pivot_root), so go through the
        // raw syscall instead of relying on an undeclared libc symbol.
        MemorySegment nr = arena.allocateFrom(newRoot);
        MemorySegment po = arena.allocateFrom(putOld);
        return (int) syscall(Constants.NR_pivot_root, nr.address(), po.address(), 0, 0, 0);
    }

    public static int chdir(Arena arena, String path) {
        return NativeH.chdir(arena.allocateFrom(path));
    }

    public static int chroot(Arena arena, String path) {
        MemorySegment p = arena.allocateFrom(path);
        return (int) syscall(Constants.NR_chroot, p.address(), 0, 0, 0, 0);
    }

    public static int sethostname(Arena arena, String name) {
        return NativeH.sethostname(arena.allocateFrom(name), name.getBytes().length);
    }

    public static int setdomainname(Arena arena, String name) {
        return NativeH.setdomainname(arena.allocateFrom(name), name.getBytes().length);
    }

    public static int kill(int pid, int signal) {
        return NativeH.kill(pid, signal);
    }

    public static int prctl(int op, long a, long b, long c, long d) {
        return PRCTL.apply(op, a, b, c, d);
    }

    public static int umask(int mask) {
        return NativeH.umask(mask);
    }

    public static int getpid() {
        return NativeH.getpid();
    }

    public static int getppid() {
        return NativeH.getppid();
    }

    public static int errno() {
        return NativeH.__errno_location().reinterpret(4).get(ValueLayout.JAVA_INT, 0);
    }

    public static String strerror(int errnum) {
        return NativeH.strerror(errnum).reinterpret(Long.MAX_VALUE).getString(0);
    }

    public static int execvp(Arena arena, String file, String[] argv) {
        return NativeH.execvp(arena.allocateFrom(file), PosixIO.cStringArray(arena, argv));
    }

    public static int clearenv() {
        return NativeH.clearenv();
    }

    public static int setenv(Arena arena, String name, String value, boolean overwrite) {
        return NativeH.setenv(arena.allocateFrom(name), arena.allocateFrom(value), overwrite ? 1 : 0);
    }

    public static int setgroups(Arena arena, int[] gids) {
        MemorySegment seg = arena.allocate(ValueLayout.JAVA_INT, gids.length);
        for (int i = 0; i < gids.length; i++) seg.setAtIndex(ValueLayout.JAVA_INT, i, gids[i]);
        return NativeH.setgroups(gids.length, seg);
    }

    public static int prlimit64(Arena arena, int pid, int resource, long softCur, long hardMax) {
        MemorySegment newLim = arena.allocate(16);
        newLim.set(ValueLayout.JAVA_LONG, 0, softCur);
        newLim.set(ValueLayout.JAVA_LONG, 8, hardMax);
        return NativeH.prlimit64(pid, resource, newLim, MemorySegment.NULL);
    }

    public static long syscall(long nr, long a1, long a2, long a3, long a4, long a5) {
        return SYSCALL.apply(nr, a1, a2, a3, a4, a5);
    }

    public static int geteuid() {
        return NativeH.geteuid();
    }

    public static int getegid() {
        return NativeH.getegid();
    }

    public static int setresuid(int ruid, int euid, int suid) {
        return NativeH.setresuid(ruid, euid, suid);
    }

    public static int setresgid(int rgid, int egid, int sgid) {
        return NativeH.setresgid(rgid, egid, sgid);
    }

    public static int mknod(Arena arena, String path, int mode, long dev) {
        return NativeH.mknod(arena.allocateFrom(path), mode, dev);
    }

    public static int chown(Arena arena, String path, int owner, int group) {
        return NativeH.chown(arena.allocateFrom(path), owner, group);
    }

    public static int ioctl(int fd, long request, MemorySegment arg) {
        return IOCTL.apply(fd, request, arg);
    }

    public static int waitpid(int pid, MemorySegment status, int options) {
        return NativeH.waitpid(pid, status, options);
    }

}
