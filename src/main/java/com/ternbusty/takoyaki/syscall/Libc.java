package com.ternbusty.takoyaki.syscall;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

public final class Libc {
    private Libc() {}

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBC = LINKER.defaultLookup();

    private static MethodHandle downcall(String name, FunctionDescriptor desc) {
        return LIBC.find(name)
                .map(addr -> LINKER.downcallHandle(addr, desc))
                .orElseThrow(() -> new UnsatisfiedLinkError("libc symbol not found: " + name));
    }

    private static final MethodHandle UNSHARE = downcall("unshare",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle SETNS = downcall("setns",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle MOUNT = downcall("mount",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    private static final MethodHandle UMOUNT2 = downcall("umount2",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    private static final MethodHandle PIVOT_ROOT = downcall("pivot_root",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle CHDIR = downcall("chdir",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    private static final MethodHandle SETHOSTNAME = downcall("sethostname",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
    private static final MethodHandle KILL = downcall("kill",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle PRCTL = downcall("prctl",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle UMASK = downcall("umask",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle GETPID = downcall("getpid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
    private static final MethodHandle GETPPID = downcall("getppid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
    private static final MethodHandle ERRNO_LOCATION = downcall("__errno_location",
            FunctionDescriptor.of(ValueLayout.ADDRESS));
    private static final MethodHandle STRERROR = downcall("strerror",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    private static final MethodHandle EXECVP = downcall("execvp",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle CLEARENV = downcall("clearenv",
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
    private static final MethodHandle SETENV = downcall("setenv",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    private static final MethodHandle SETGROUPS = downcall("setgroups",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    private static final MethodHandle PRLIMIT64 = downcall("prlimit64",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SYSCALL = downcall("syscall",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle GETEUID = downcall("geteuid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
    private static final MethodHandle GETEGID = downcall("getegid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT));
    private static final MethodHandle SETRESUID = downcall("setresuid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle SETRESGID = downcall("setresgid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle MKNOD = downcall("mknod",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
    private static final MethodHandle IOCTL = downcall("ioctl",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    private static final MethodHandle WAITPID = downcall("waitpid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    public static int unshare(int flags) {
        try {
            return (int) UNSHARE.invoke(flags);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int setns(int fd, int nstype) {
        try {
            return (int) SETNS.invoke(fd, nstype);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int mount(Arena arena, String source, String target, String fstype, long flags, String data) {
        try {
            MemorySegment src = source == null ? MemorySegment.NULL : arena.allocateFrom(source);
            MemorySegment tgt = arena.allocateFrom(target);
            MemorySegment fs = fstype == null ? MemorySegment.NULL : arena.allocateFrom(fstype);
            MemorySegment dt = data == null ? MemorySegment.NULL : arena.allocateFrom(data);
            return (int) MOUNT.invoke(src, tgt, fs, flags, dt);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int umount2(Arena arena, String target, int flags) {
        try {
            return (int) UMOUNT2.invoke(arena.allocateFrom(target), flags);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int pivotRoot(Arena arena, String newRoot, String putOld) {
        try {
            return (int) PIVOT_ROOT.invoke(
                    arena.allocateFrom(newRoot),
                    arena.allocateFrom(putOld));
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int chdir(Arena arena, String path) {
        try {
            return (int) CHDIR.invoke(arena.allocateFrom(path));
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int sethostname(Arena arena, String name) {
        try {
            MemorySegment seg = arena.allocateFrom(name);
            return (int) SETHOSTNAME.invoke(seg, (long) name.getBytes().length);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int kill(int pid, int signal) {
        try {
            return (int) KILL.invoke(pid, signal);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int prctl(int op, long a, long b, long c, long d) {
        try {
            return (int) PRCTL.invoke(op, a, b, c, d);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int umask(int mask) {
        try {
            return (int) UMASK.invoke(mask);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int getpid() {
        try {
            return (int) GETPID.invoke();
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int getppid() {
        try {
            return (int) GETPPID.invoke();
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int errno() {
        try {
            MemorySegment ptr = (MemorySegment) ERRNO_LOCATION.invoke();
            return ptr.reinterpret(4).get(ValueLayout.JAVA_INT, 0);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static String strerror(int errnum) {
        try {
            MemorySegment ptr = (MemorySegment) STRERROR.invoke(errnum);
            return ptr.reinterpret(Long.MAX_VALUE).getString(0);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int execvp(Arena arena, String file, String[] argv) {
        try {
            MemorySegment argvArr = PosixIO.cStringArray(arena, argv);
            return (int) EXECVP.invoke(arena.allocateFrom(file), argvArr);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int clearenv() {
        try {
            return (int) CLEARENV.invoke();
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int setenv(Arena arena, String name, String value, boolean overwrite) {
        try {
            return (int) SETENV.invoke(
                    arena.allocateFrom(name),
                    arena.allocateFrom(value),
                    overwrite ? 1 : 0);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int setgroups(Arena arena, int[] gids) {
        try {
            MemorySegment seg = arena.allocate(ValueLayout.JAVA_INT, gids.length);
            for (int i = 0; i < gids.length; i++) seg.setAtIndex(ValueLayout.JAVA_INT, i, gids[i]);
            return (int) SETGROUPS.invoke((long) gids.length, seg);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int prlimit64(Arena arena, int pid, int resource, long softCur, long hardMax) {
        try {
            MemorySegment newLim = arena.allocate(16);
            newLim.set(ValueLayout.JAVA_LONG, 0, softCur);
            newLim.set(ValueLayout.JAVA_LONG, 8, hardMax);
            return (int) PRLIMIT64.invoke(pid, resource, newLim, MemorySegment.NULL);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static long syscall(long nr, long a1, long a2, long a3, long a4, long a5) {
        try {
            return (long) SYSCALL.invoke(nr, a1, a2, a3, a4, a5);
        } catch (Throwable t) { throw sneaky(t); }
    }

    public static int geteuid() {
        try { return (int) GETEUID.invoke(); }
        catch (Throwable t) { throw sneaky(t); }
    }

    public static int getegid() {
        try { return (int) GETEGID.invoke(); }
        catch (Throwable t) { throw sneaky(t); }
    }

    public static int setresuid(int ruid, int euid, int suid) {
        try { return (int) SETRESUID.invoke(ruid, euid, suid); }
        catch (Throwable t) { throw sneaky(t); }
    }

    public static int setresgid(int rgid, int egid, int sgid) {
        try { return (int) SETRESGID.invoke(rgid, egid, sgid); }
        catch (Throwable t) { throw sneaky(t); }
    }

    public static int mknod(Arena arena, String path, int mode, long dev) {
        try { return (int) MKNOD.invoke(arena.allocateFrom(path), mode, dev); }
        catch (Throwable t) { throw sneaky(t); }
    }

    public static int ioctl(int fd, long request, MemorySegment arg) {
        try { return (int) IOCTL.invoke(fd, request, arg); }
        catch (Throwable t) { throw sneaky(t); }
    }

    public static int waitpid(int pid, MemorySegment status, int options) {
        try { return (int) WAITPID.invoke(pid, status, options); }
        catch (Throwable t) { throw sneaky(t); }
    }

    private static RuntimeException sneaky(Throwable t) {
        if (t instanceof RuntimeException re) return re;
        if (t instanceof Error e) throw e;
        return new RuntimeException(t);
    }
}
