package com.ternbusty.takoyaki.syscall

import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

/**
 * Real-kernel implementation of [Syscalls].
 *
 * Just forwards to the existing [Libc] / [PosixIO] statics -- those
 * stay in place during the migration so any code not yet ported keeps working.
 * Once every callsite goes through [Syscalls], we can drop direct static
 * calls and inline the Panama FFM bits here.
 */
class LinuxSyscalls : Syscalls {

    override fun mount(source: String?, target: String, fstype: String?, flags: Long, data: String?): Int {
        Arena.ofConfined().use { arena ->
            return Libc.mount(arena, source, target, fstype, flags, data)
        }
    }

    override fun umount2(target: String, flags: Int): Int {
        Arena.ofConfined().use { arena ->
            return Libc.umount2(arena, target, flags)
        }
    }

    override fun errno(): Int = Libc.errno()

    override fun strerror(errnum: Int): String = Libc.strerror(errnum)

    override fun kill(pid: Int, sig: Int): Int = Libc.kill(pid, sig)

    override fun syscall(nr: Long, a1: Long, a2: Long, a3: Long, a4: Long, a5: Long): Long =
        Libc.syscall(nr, a1, a2, a3, a4, a5)

    override fun prlimit64(pid: Int, resource: Int, soft: Long, hard: Long): Int {
        Arena.ofConfined().use { arena ->
            return Libc.prlimit64(arena, pid, resource, soft, hard)
        }
    }

    /** ifreq layout: name[16] + flags at offset 16. Buffer is 40 bytes total. */
    companion object {
        private const val IFNAMSIZ = 16
        private const val IFREQ_SIZE = 40
    }

    override fun ifUp(ifaceName: String): Int {
        Arena.ofConfined().use { arena ->
            val fd = PosixIO.socket(Constants.AF_INET, Constants.SOCK_DGRAM, 0)
            if (fd < 0) return -1
            try {
                val ifr = arena.allocate(IFREQ_SIZE.toLong(), 8)
                val name = "$ifaceName\u0000".toByteArray()
                for (i in 0 until minOf(name.size, IFNAMSIZ)) {
                    ifr.set(ValueLayout.JAVA_BYTE, i.toLong(), name[i])
                }
                if (Libc.ioctl(fd, Constants.SIOCGIFFLAGS, ifr) != 0) return -1
                var flags = ifr.get(ValueLayout.JAVA_SHORT, IFNAMSIZ.toLong())
                flags = (flags.toInt() or Constants.IFF_UP).toShort()
                ifr.set(ValueLayout.JAVA_SHORT, IFNAMSIZ.toLong(), flags)
                if (Libc.ioctl(fd, Constants.SIOCSIFFLAGS, ifr) != 0) return -1
                return 0
            } finally {
                PosixIO.close(fd)
            }
        }
    }

    override fun keyctlJoinSessionKeyring(name: String?): Long {
        val nr = Constants.NR_keyctl
        var arena: Arena? = null
        try {
            val arg = if (name != null) {
                arena = Arena.ofConfined()
                arena!!.allocateFrom(name).address()
            } else {
                0L
            }
            return Libc.syscall(nr, Constants.KEYCTL_JOIN_SESSION_KEYRING.toLong(),
                arg, 0, 0, 0)
        } finally {
            arena?.close()
        }
    }

    override fun mknod(path: String, mode: Int, dev: Long): Int {
        Arena.ofConfined().use { arena ->
            return Libc.mknod(arena, path, mode, dev)
        }
    }

    override fun access(path: String, mode: Int): Int {
        Arena.ofConfined().use { arena ->
            return PosixIO.access(arena, path, mode)
        }
    }
}
