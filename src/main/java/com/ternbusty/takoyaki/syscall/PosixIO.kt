package com.ternbusty.takoyaki.syscall

import com.ternbusty.takoyaki.syscall.gen.NativeH
import com.ternbusty.takoyaki.syscall.gen.NativeH_4
import com.ternbusty.takoyaki.syscall.gen.__CONST_SOCKADDR_ARG
import com.ternbusty.takoyaki.syscall.gen.__SOCKADDR_ARG
import com.ternbusty.takoyaki.syscall.gen.sockaddr_un
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * POSIX socket and file IO over the jextract-generated [NativeH] bindings.
 * Struct layouts (sockaddr_un) come from the generated accessors rather than
 * hand-written offsets.
 */
object PosixIO {

    // open(2) and fcntl(2) are variadic; jextract exposes them through an
    // invoker factory, so bind the fixed shapes takoyaki uses.
    private val OPEN: NativeH_4.open = NativeH_4.open.makeInvoker(Layouts.C_INT)
    private val FCNTL: NativeH_4.fcntl = NativeH_4.fcntl.makeInvoker(Layouts.C_INT)

    /**
     * glibc declares bind/connect/accept with transparent unions over sockaddr*,
     * so the generated bindings take the union by value. It is a single pointer
     * wide: allocate one and point its sockaddr_un member at the address.
     */
    private fun constSockaddrArg(arena: Arena, sockaddr: MemorySegment): MemorySegment {
        val arg = __CONST_SOCKADDR_ARG.allocate(arena)
        __CONST_SOCKADDR_ARG.__sockaddr_un__(arg, sockaddr)
        return arg
    }

    fun socketpair(arena: Arena, domain: Int, type: Int, protocol: Int, fds: IntArray): Int {
        val seg = arena.allocate(ValueLayout.JAVA_INT, 2)
        val rc = NativeH.socketpair(domain, type, protocol, seg)
        if (rc == 0) {
            fds[0] = seg.getAtIndex(ValueLayout.JAVA_INT, 0)
            fds[1] = seg.getAtIndex(ValueLayout.JAVA_INT, 1)
        }
        return rc
    }

    fun socket(domain: Int, type: Int, protocol: Int): Int =
        NativeH.socket(domain, type, protocol)

    fun bindUnix(arena: Arena, fd: Int, path: String): Int {
        val pb = path.toByteArray()
        val arg = constSockaddrArg(arena, sockaddrUn(arena, pb))
        return NativeH.bind(fd, arg, sockaddrUnLen(pb))
    }

    fun connectUnix(arena: Arena, fd: Int, path: String): Int {
        val pb = path.toByteArray()
        val arg = constSockaddrArg(arena, sockaddrUn(arena, pb))
        return NativeH.connect(fd, arg, sockaddrUnLen(pb))
    }

    /** sun_family + the NUL-terminated path, which is what the kernel expects. */
    private fun sockaddrUnLen(pathBytes: ByteArray): Int =
        sockaddr_un.`sun_path$offset`().toInt() + pathBytes.size + 1

    private fun sockaddrUn(arena: Arena, pathBytes: ByteArray): MemorySegment {
        val addr = sockaddr_un.allocate(arena)
        sockaddr_un.sun_family(addr, NativeH.AF_UNIX().toShort())
        val sunPath = sockaddr_un.sun_path(addr)
        if (pathBytes.size >= sunPath.byteSize()) {
            throw IllegalArgumentException("socket path too long")
        }
        MemorySegment.copy(pathBytes, 0, sunPath, ValueLayout.JAVA_BYTE, 0, pathBytes.size)
        sunPath.set(ValueLayout.JAVA_BYTE, pathBytes.size.toLong(), 0.toByte())
        return addr
    }

    fun listen(fd: Int, backlog: Int): Int = NativeH.listen(fd, backlog)

    fun accept(fd: Int): Int {
        Arena.ofConfined().use { arena ->
            // NULL addr/addrlen: we do not care who connected.
            val arg = __SOCKADDR_ARG.allocate(arena)
            __SOCKADDR_ARG.__sockaddr_un__(arg, MemorySegment.NULL)
            return NativeH.accept(fd, arg, MemorySegment.NULL)
        }
    }

    fun read(arena: Arena, fd: Int, buf: ByteArray): Long {
        val seg = arena.allocate(buf.size.toLong())
        val n = NativeH.read(fd, seg, buf.size.toLong())
        if (n > 0) MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, 0, buf, 0, n.toInt())
        return n
    }

    fun write(arena: Arena, fd: Int, buf: ByteArray): Long {
        val seg = arena.allocate(buf.size.toLong())
        MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, buf.size)
        return NativeH.write(fd, seg, buf.size.toLong())
    }

    fun send(arena: Arena, fd: Int, buf: ByteArray, flags: Int): Long {
        val seg = arena.allocate(buf.size.toLong())
        MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, buf.size)
        return NativeH.send(fd, seg, buf.size.toLong(), flags)
    }

    fun recv(arena: Arena, fd: Int, buf: ByteArray, flags: Int): Long {
        val seg = arena.allocate(buf.size.toLong())
        val n = NativeH.recv(fd, seg, buf.size.toLong(), flags)
        if (n > 0) MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, 0, buf, 0, n.toInt())
        return n
    }

    /**
     * Bind a socket to an arbitrary sockaddr (e.g. sockaddr_nl for netlink).
     * Unlike [bindUnix] this does not construct a sockaddr_un; the
     * caller is responsible for building the appropriate address structure.
     */
    fun bindRaw(arena: Arena, fd: Int, sockaddr: MemorySegment, addrlen: Int): Int {
        val arg = constSockaddrArg(arena, sockaddr)
        return NativeH.bind(fd, arg, addrlen)
    }

    /** Send from a MemorySegment buffer (for netlink / raw protocols). */
    fun sendRaw(fd: Int, buf: MemorySegment, len: Long, flags: Int): Long =
        NativeH.send(fd, buf, len, flags)

    /** Receive into a MemorySegment buffer (for netlink / raw protocols). */
    fun recvRaw(fd: Int, buf: MemorySegment, len: Long, flags: Int): Long =
        NativeH.recv(fd, buf, len, flags)

    fun close(fd: Int): Int = NativeH.close(fd)

    /**
     * Write the whole buffer, retrying short writes and EINTR. The native
     * segment is allocated once and advanced by slicing, so a fragmented
     * write of a large buffer costs no per-iteration heap copies.
     * Returns true on success, false on a write error (errno preserved).
     */
    fun writeAll(arena: Arena, fd: Int, buf: ByteArray): Boolean {
        val seg = arena.allocate(buf.size.toLong())
        MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, buf.size)
        var off = 0L
        while (off < buf.size) {
            val n = NativeH.write(fd, seg.asSlice(off), buf.size - off)
            if (n < 0) {
                if (Libc.errno() == Constants.EINTR) continue
                return false
            }
            if (n == 0L) return false
            off += n
        }
        return true
    }

    fun unlink(arena: Arena, path: String): Int =
        NativeH.unlink(arena.allocateFrom(path))

    fun access(arena: Arena, path: String, mode: Int): Int =
        NativeH.access(arena.allocateFrom(path), mode)

    fun open(arena: Arena, path: String, flags: Int, mode: Int): Int =
        OPEN.apply(arena.allocateFrom(path), flags, mode)

    fun fchdir(fd: Int): Int = NativeH.fchdir(fd)

    fun fork(): Int = NativeH.fork()

    fun _exit(status: Int) {
        NativeH._exit(status)
    }

    fun invokeExecve(p: ExecvePayload): Int =
        NativeH.execve(p.path, p.argv, p.envp)

    class ExecvePayload private constructor(
        val path: MemorySegment,
        val argv: MemorySegment,
        val envp: MemorySegment,
    ) {
        companion object {
            fun build(arena: Arena, path: String, argv: Array<String>, envp: Array<String>): ExecvePayload {
                val pathSeg = arena.allocateFrom(path)
                val argvArr = cStringArray(arena, argv)
                val envArr = cStringArray(arena, envp)
                return ExecvePayload(pathSeg, argvArr, envArr)
            }
        }
    }

    /** NULL-terminated array of C strings (argv/envp shape). Shared with [Libc.execvp]. */
    internal fun cStringArray(arena: Arena, strings: Array<String>): MemorySegment {
        val arr = arena.allocate(ValueLayout.ADDRESS, strings.size + 1L)
        for (i in strings.indices) {
            arr.setAtIndex(ValueLayout.ADDRESS, i.toLong(), arena.allocateFrom(strings[i]))
        }
        arr.setAtIndex(ValueLayout.ADDRESS, strings.size.toLong(), MemorySegment.NULL)
        return arr
    }

    fun fcntl(fd: Int, op: Int, arg: Int): Int = FCNTL.apply(fd, op, arg)

    fun readlink(arena: Arena, path: String): String? {
        val p = arena.allocateFrom(path)
        val buf = arena.allocate(4096)
        val n = NativeH.readlink(p, buf, 4095L)
        if (n < 0) return null
        val b = ByteArray(n.toInt())
        MemorySegment.copy(buf, ValueLayout.JAVA_BYTE, 0, b, 0, n.toInt())
        return String(b)
    }
}
