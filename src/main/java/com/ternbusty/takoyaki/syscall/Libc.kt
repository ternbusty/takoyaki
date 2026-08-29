package com.ternbusty.takoyaki.syscall

import com.ternbusty.takoyaki.syscall.gen.NativeH
import com.ternbusty.takoyaki.syscall.gen.NativeH_3
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * libc facade over the jextract-generated [NativeH] bindings. The public
 * surface is unchanged (Arena/String in, int/long out) so callers and the
 * `MockedStatic<Libc>` unit tests are unaffected; only the plumbing moved
 * from hand-written FFM downcalls to generated ones.
 *
 * Variadic functions (prctl, syscall, ioctl) are called through jextract's
 * `makeInvoker` factory with the fixed argument layouts takoyaki uses.
 */
object Libc {

    private val PRCTL: NativeH_3.prctl =
        NativeH_3.prctl.makeInvoker(Layouts.C_LONG, Layouts.C_LONG, Layouts.C_LONG, Layouts.C_LONG)
    private val SYSCALL: NativeH_3.syscall =
        NativeH_3.syscall.makeInvoker(Layouts.C_LONG, Layouts.C_LONG, Layouts.C_LONG, Layouts.C_LONG, Layouts.C_LONG)
    private val IOCTL: NativeH_3.ioctl =
        NativeH_3.ioctl.makeInvoker(Layouts.C_POINTER)

    @JvmStatic
    fun unshare(flags: Int): Int = NativeH.unshare(flags)

    @JvmStatic
    fun setns(fd: Int, nstype: Int): Int = NativeH.setns(fd, nstype)

    @JvmStatic
    fun mount(arena: Arena, source: String?, target: String, fstype: String?, flags: Long, data: String?): Int {
        val src = source?.let { arena.allocateFrom(it) } ?: MemorySegment.NULL
        val tgt = arena.allocateFrom(target)
        val fs = fstype?.let { arena.allocateFrom(it) } ?: MemorySegment.NULL
        val dt = data?.let { arena.allocateFrom(it) } ?: MemorySegment.NULL
        return NativeH.mount(src, tgt, fs, flags, dt)
    }

    @JvmStatic
    fun umount2(arena: Arena, target: String, flags: Int): Int =
        NativeH.umount2(arena.allocateFrom(target), flags)

    @JvmStatic
    fun pivotRoot(arena: Arena, newRoot: String, putOld: String): Int {
        // glibc has no pivot_root wrapper (man 2 pivot_root), so go through the
        // raw syscall instead of relying on an undeclared libc symbol.
        val nr = arena.allocateFrom(newRoot)
        val po = arena.allocateFrom(putOld)
        return syscall(Constants.NR_pivot_root, nr.address(), po.address(), 0, 0, 0).toInt()
    }

    @JvmStatic
    fun chdir(arena: Arena, path: String): Int =
        NativeH.chdir(arena.allocateFrom(path))

    @JvmStatic
    fun chroot(arena: Arena, path: String): Int {
        val p = arena.allocateFrom(path)
        return syscall(Constants.NR_chroot, p.address(), 0, 0, 0, 0).toInt()
    }

    @JvmStatic
    fun sethostname(arena: Arena, name: String): Int =
        NativeH.sethostname(arena.allocateFrom(name), name.toByteArray().size.toLong())

    @JvmStatic
    fun setdomainname(arena: Arena, name: String): Int =
        NativeH.setdomainname(arena.allocateFrom(name), name.toByteArray().size.toLong())

    @JvmStatic
    fun kill(pid: Int, signal: Int): Int = NativeH.kill(pid, signal)

    @JvmStatic
    fun prctl(op: Int, a: Long, b: Long, c: Long, d: Long): Int =
        PRCTL.apply(op, a, b, c, d)

    @JvmStatic
    fun umask(mask: Int): Int = NativeH.umask(mask)

    @JvmStatic
    fun getpid(): Int = NativeH.getpid()

    @JvmStatic
    fun getppid(): Int = NativeH.getppid()

    @JvmStatic
    fun errno(): Int =
        NativeH.__errno_location().reinterpret(4).get(ValueLayout.JAVA_INT, 0)

    @JvmStatic
    fun strerror(errnum: Int): String =
        NativeH.strerror(errnum).reinterpret(Long.MAX_VALUE).getString(0)

    @JvmStatic
    fun execvp(arena: Arena, file: String, argv: Array<String>): Int =
        NativeH.execvp(arena.allocateFrom(file), PosixIO.cStringArray(arena, argv))

    @JvmStatic
    fun clearenv(): Int = NativeH.clearenv()

    @JvmStatic
    fun setenv(arena: Arena, name: String, value: String, overwrite: Boolean): Int =
        NativeH.setenv(arena.allocateFrom(name), arena.allocateFrom(value), if (overwrite) 1 else 0)

    @JvmStatic
    fun setgroups(arena: Arena, gids: IntArray): Int {
        val seg = arena.allocate(ValueLayout.JAVA_INT, gids.size.toLong())
        for (i in gids.indices) seg.setAtIndex(ValueLayout.JAVA_INT, i.toLong(), gids[i])
        return NativeH.setgroups(gids.size.toLong(), seg)
    }

    @JvmStatic
    fun prlimit64(arena: Arena, pid: Int, resource: Int, softCur: Long, hardMax: Long): Int {
        val newLim = arena.allocate(16)
        newLim.set(ValueLayout.JAVA_LONG, 0, softCur)
        newLim.set(ValueLayout.JAVA_LONG, 8, hardMax)
        return NativeH.prlimit64(pid, resource, newLim, MemorySegment.NULL)
    }

    @JvmStatic
    fun syscall(nr: Long, a1: Long, a2: Long, a3: Long, a4: Long, a5: Long): Long =
        SYSCALL.apply(nr, a1, a2, a3, a4, a5)

    @JvmStatic
    fun geteuid(): Int = NativeH.geteuid()

    @JvmStatic
    fun getegid(): Int = NativeH.getegid()

    @JvmStatic
    fun setresuid(ruid: Int, euid: Int, suid: Int): Int =
        NativeH.setresuid(ruid, euid, suid)

    @JvmStatic
    fun setresgid(rgid: Int, egid: Int, sgid: Int): Int =
        NativeH.setresgid(rgid, egid, sgid)

    @JvmStatic
    fun mknod(arena: Arena, path: String, mode: Int, dev: Long): Int =
        NativeH.mknod(arena.allocateFrom(path), mode, dev)

    @JvmStatic
    fun chown(arena: Arena, path: String, owner: Int, group: Int): Int =
        NativeH.chown(arena.allocateFrom(path), owner, group)

    @JvmStatic
    fun ioctl(fd: Int, request: Long, arg: MemorySegment): Int =
        IOCTL.apply(fd, request, arg)

    @JvmStatic
    fun waitpid(pid: Int, status: MemorySegment, options: Int): Int =
        NativeH.waitpid(pid, status, options)
}
