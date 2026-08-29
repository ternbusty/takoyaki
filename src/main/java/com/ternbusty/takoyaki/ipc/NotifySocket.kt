package com.ternbusty.takoyaki.ipc

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Constants.AF_UNIX
import com.ternbusty.takoyaki.syscall.Constants.SOCK_STREAM
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import java.lang.foreign.Arena

object NotifySocket {

    /** Canonical notify socket path for a container. Single owner of the naming scheme. */
    fun pathFor(containerId: String): String = "/tmp/takoyaki-$containerId.sock"

    fun createListener(socketPath: String): Int {
        Arena.ofConfined().use { arena ->
            val fd = PosixIO.socket(AF_UNIX, SOCK_STREAM, 0)
            if (fd < 0) throw RuntimeException("socket: ${Libc.strerror(Libc.errno())}")
            PosixIO.unlink(arena, socketPath)
            if (PosixIO.bindUnix(arena, fd, socketPath) < 0) {
                val e = Libc.errno()
                PosixIO.close(fd)
                throw RuntimeException("bind $socketPath: ${Libc.strerror(e)}")
            }
            if (PosixIO.listen(fd, 1) < 0) {
                val e = Libc.errno()
                PosixIO.close(fd)
                throw RuntimeException("listen: ${Libc.strerror(e)}")
            }
            Logger.debug("notify listener bound on $socketPath fd=$fd")
            return fd
        }
    }

    fun waitForStart(listenFd: Int) {
        val cs = PosixIO.accept(listenFd)
        if (cs < 0) throw RuntimeException("accept: ${Libc.strerror(Libc.errno())}")
        try {
            Arena.ofConfined().use { arena ->
                val buf = ByteArray(256)
                val n = PosixIO.recv(arena, cs, buf, 0)
                if (n < 0) throw RuntimeException("recv: ${Libc.strerror(Libc.errno())}")
                Logger.debug("notify listener received: ${String(buf, 0, maxOf(0L, n).toInt())}")
            }
        } finally {
            PosixIO.close(cs)
        }
    }

    fun sendStart(socketPath: String) {
        Arena.ofConfined().use { arena ->
            val fd = PosixIO.socket(AF_UNIX, SOCK_STREAM, 0)
            if (fd < 0) throw RuntimeException("socket: ${Libc.strerror(Libc.errno())}")
            try {
                if (PosixIO.connectUnix(arena, fd, socketPath) < 0) {
                    throw RuntimeException("connect $socketPath: ${Libc.strerror(Libc.errno())}")
                }
                val msg = "start container".toByteArray()
                val n = PosixIO.send(arena, fd, msg, 0)
                if (n < 0) throw RuntimeException("send: ${Libc.strerror(Libc.errno())}")
                Logger.debug("notify sent start to $socketPath")
            } finally {
                PosixIO.close(fd)
            }
        }
    }
}
