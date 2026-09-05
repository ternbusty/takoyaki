package com.ternbusty.takoyaki.console

import com.ternbusty.takoyaki.ipc.ScmRights
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO

import java.lang.foreign.Arena

/**
 * Send a pidfd for a container init process to the caller via a Unix socket.
 * The --pidfd-socket flag provides the socket path. The caller (e.g.
 * pidfd-kill) receives the fd and can use pidfd_send_signal() on it.
 */
class PidfdSocket private constructor() {

    companion object {

        /**
         * Open a pidfd for [pid], send it to the Unix socket at
         * [socketPath] via SCM_RIGHTS, then close both the pidfd and the
         * socket. Returns true on success.
         */
        fun sendPidfd(socketPath: String, pid: Int): Boolean {
            Arena.ofConfined().use { arena ->
                // pidfd_open(pid, 0)
                val pidfd = Libc.syscall(Constants.NR_pidfd_open, pid.toLong(), 0L, 0L, 0L, 0L)
                if (pidfd < 0) {
                    Logger.warn("pidfd_open($pid): ${Libc.strerror(Libc.errno())}")
                    return false
                }
                val fd = pidfd.toInt()
                try {
                    val sock = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0)
                    if (sock < 0) {
                        Logger.warn("socket for pidfd-socket: ${Libc.strerror(Libc.errno())}")
                        return false
                    }
                    try {
                        if (PosixIO.connectUnix(arena, sock, socketPath) < 0) {
                            Logger.warn("connect $socketPath: ${Libc.strerror(Libc.errno())}")
                            return false
                        }
                        val ok = ScmRights.sendFd(sock, fd, 0.toByte())
                        if (ok) {
                            Logger.debug("pidfd for pid $pid sent to $socketPath")
                        }
                        return ok
                    } finally {
                        PosixIO.close(sock)
                    }
                } finally {
                    PosixIO.close(fd)
                }
            }
        }
    }
}
