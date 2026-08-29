package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.syscall.gen.NativeH;
import com.ternbusty.takoyaki.syscall.gen.__CONST_SOCKADDR_ARG;
import com.ternbusty.takoyaki.syscall.gen.__SOCKADDR_ARG;
import com.ternbusty.takoyaki.syscall.gen.sockaddr_un;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * POSIX socket and file IO over the jextract-generated {@link NativeH} bindings.
 * Struct layouts (sockaddr_un) come from the generated accessors rather than
 * hand-written offsets.
 */
public final class PosixIO {
    private PosixIO() {}

    // open(2) and fcntl(2) are variadic; jextract exposes them through an
    // invoker factory, so bind the fixed shapes takoyaki uses.
    private static final NativeH.open OPEN = NativeH.open.makeInvoker(NativeH.C_INT);
    private static final NativeH.fcntl FCNTL = NativeH.fcntl.makeInvoker(NativeH.C_INT);

    /**
     * glibc declares bind/connect/accept with transparent unions over sockaddr*,
     * so the generated bindings take the union by value. It is a single pointer
     * wide: allocate one and point its sockaddr_un member at the address.
     */
    private static MemorySegment constSockaddrArg(Arena arena, MemorySegment sockaddr) {
        MemorySegment arg = __CONST_SOCKADDR_ARG.allocate(arena);
        __CONST_SOCKADDR_ARG.__sockaddr_un__(arg, sockaddr);
        return arg;
    }

    public static int socketpair(Arena arena, int domain, int type, int protocol, int[] fds) {
        MemorySegment seg = arena.allocate(ValueLayout.JAVA_INT, 2);
        int rc = NativeH.socketpair(domain, type, protocol, seg);
        if (rc == 0) {
            fds[0] = seg.getAtIndex(ValueLayout.JAVA_INT, 0);
            fds[1] = seg.getAtIndex(ValueLayout.JAVA_INT, 1);
        }
        return rc;
    }

    public static int socket(int domain, int type, int protocol) {
        return NativeH.socket(domain, type, protocol);
    }

    public static int bindUnix(Arena arena, int fd, String path) {
        byte[] pb = path.getBytes();
        MemorySegment arg = constSockaddrArg(arena, sockaddrUn(arena, pb));
        return NativeH.bind(fd, arg, sockaddrUnLen(pb));
    }

    public static int connectUnix(Arena arena, int fd, String path) {
        byte[] pb = path.getBytes();
        MemorySegment arg = constSockaddrArg(arena, sockaddrUn(arena, pb));
        return NativeH.connect(fd, arg, sockaddrUnLen(pb));
    }

    /** sun_family + the NUL-terminated path, which is what the kernel expects. */
    private static int sockaddrUnLen(byte[] pathBytes) {
        return (int) sockaddr_un.sun_path$offset() + pathBytes.length + 1;
    }

    private static MemorySegment sockaddrUn(Arena arena, byte[] pathBytes) {
        MemorySegment addr = sockaddr_un.allocate(arena);
        sockaddr_un.sun_family(addr, (short) NativeH.AF_UNIX());
        MemorySegment sunPath = sockaddr_un.sun_path(addr);
        if (pathBytes.length >= sunPath.byteSize()) {
            throw new IllegalArgumentException("socket path too long");
        }
        MemorySegment.copy(pathBytes, 0, sunPath, ValueLayout.JAVA_BYTE, 0, pathBytes.length);
        sunPath.set(ValueLayout.JAVA_BYTE, pathBytes.length, (byte) 0);
        return addr;
    }

    public static int listen(int fd, int backlog) {
        return NativeH.listen(fd, backlog);
    }

    public static int accept(int fd) {
        try (Arena arena = Arena.ofConfined()) {
            // NULL addr/addrlen: we do not care who connected.
            MemorySegment arg = __SOCKADDR_ARG.allocate(arena);
            __SOCKADDR_ARG.__sockaddr_un__(arg, MemorySegment.NULL);
            return NativeH.accept(fd, arg, MemorySegment.NULL);
        }
    }

    public static long read(Arena arena, int fd, byte[] buf) {
        MemorySegment seg = arena.allocate(buf.length);
        long n = NativeH.read(fd, seg, buf.length);
        if (n > 0) MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, 0, buf, 0, (int) n);
        return n;
    }

    public static long write(Arena arena, int fd, byte[] buf) {
        MemorySegment seg = arena.allocate(buf.length);
        MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, buf.length);
        return NativeH.write(fd, seg, buf.length);
    }

    public static long send(Arena arena, int fd, byte[] buf, int flags) {
        MemorySegment seg = arena.allocate(buf.length);
        MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, buf.length);
        return NativeH.send(fd, seg, buf.length, flags);
    }

    public static long recv(Arena arena, int fd, byte[] buf, int flags) {
        MemorySegment seg = arena.allocate(buf.length);
        long n = NativeH.recv(fd, seg, buf.length, flags);
        if (n > 0) MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, 0, buf, 0, (int) n);
        return n;
    }

    /**
     * Bind a socket to an arbitrary sockaddr (e.g. sockaddr_nl for netlink).
     * Unlike {@link #bindUnix} this does not construct a sockaddr_un; the
     * caller is responsible for building the appropriate address structure.
     */
    public static int bindRaw(Arena arena, int fd, MemorySegment sockaddr, int addrlen) {
        MemorySegment arg = constSockaddrArg(arena, sockaddr);
        return NativeH.bind(fd, arg, addrlen);
    }

    /** Send from a MemorySegment buffer (for netlink / raw protocols). */
    public static long sendRaw(int fd, MemorySegment buf, long len, int flags) {
        return NativeH.send(fd, buf, len, flags);
    }

    /** Receive into a MemorySegment buffer (for netlink / raw protocols). */
    public static long recvRaw(int fd, MemorySegment buf, long len, int flags) {
        return NativeH.recv(fd, buf, len, flags);
    }

    public static int close(int fd) {
        return NativeH.close(fd);
    }

    /**
     * Write the whole buffer, retrying short writes and EINTR. The native
     * segment is allocated once and advanced by slicing, so a fragmented
     * write of a large buffer costs no per-iteration heap copies.
     * Returns true on success, false on a write error (errno preserved).
     */
    public static boolean writeAll(Arena arena, int fd, byte[] buf) {
        MemorySegment seg = arena.allocate(buf.length);
        MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, buf.length);
        long off = 0;
        while (off < buf.length) {
            long n = NativeH.write(fd, seg.asSlice(off), buf.length - off);
            if (n < 0) {
                if (Libc.errno() == Constants.EINTR) continue;
                return false;
            }
            if (n == 0) return false;
            off += n;
        }
        return true;
    }

    public static int unlink(Arena arena, String path) {
        return NativeH.unlink(arena.allocateFrom(path));
    }

    public static int access(Arena arena, String path, int mode) {
        return NativeH.access(arena.allocateFrom(path), mode);
    }

    public static int open(Arena arena, String path, int flags, int mode) {
        return OPEN.apply(arena.allocateFrom(path), flags, mode);
    }

    public static int fchdir(int fd) {
        return NativeH.fchdir(fd);
    }

    public static int fork() {
        return NativeH.fork();
    }

    public static void _exit(int status) {
        NativeH._exit(status);
    }

    public static int invokeExecve(ExecvePayload p) {
        return NativeH.execve(p.path, p.argv, p.envp);
    }

    public static final class ExecvePayload {
        public final MemorySegment path;
        public final MemorySegment argv;
        public final MemorySegment envp;
        private ExecvePayload(MemorySegment path, MemorySegment argv, MemorySegment envp) {
            this.path = path; this.argv = argv; this.envp = envp;
        }
        public static ExecvePayload build(Arena arena, String path, String[] argv, String[] envp) {
            MemorySegment pathSeg = arena.allocateFrom(path);
            MemorySegment argvArr = cStringArray(arena, argv);
            MemorySegment envArr = cStringArray(arena, envp);
            return new ExecvePayload(pathSeg, argvArr, envArr);
        }
    }

    /** NULL-terminated array of C strings (argv/envp shape). Shared with {@link Libc#execvp}. */
    static MemorySegment cStringArray(Arena arena, String[] strings) {
        MemorySegment arr = arena.allocate(ValueLayout.ADDRESS, strings.length + 1L);
        for (int i = 0; i < strings.length; i++) {
            arr.setAtIndex(ValueLayout.ADDRESS, i, arena.allocateFrom(strings[i]));
        }
        arr.setAtIndex(ValueLayout.ADDRESS, strings.length, MemorySegment.NULL);
        return arr;
    }

    public static int fcntl(int fd, int op, int arg) {
        return FCNTL.apply(fd, op, arg);
    }

    public static String readlink(Arena arena, String path) {
        MemorySegment p = arena.allocateFrom(path);
        MemorySegment buf = arena.allocate(4096);
        long n = NativeH.readlink(p, buf, 4095L);
        if (n < 0) return null;
        byte[] b = new byte[(int) n];
        MemorySegment.copy(buf, ValueLayout.JAVA_BYTE, 0, b, 0, (int) n);
        return new String(b);
    }
}
