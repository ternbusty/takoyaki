package com.ternbusty.takoyaki.console;

import com.ternbusty.takoyaki.ipc.ScmRights;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.lang.foreign.Arena;

/**
 * Send a pidfd for a container init process to the caller via a Unix socket.
 * The --pidfd-socket flag provides the socket path. The caller (e.g.
 * pidfd-kill) receives the fd and can use pidfd_send_signal() on it.
 */
public final class PidfdSocket {
    private PidfdSocket() {}

    /**
     * Open a pidfd for {@code pid}, send it to the Unix socket at
     * {@code socketPath} via SCM_RIGHTS, then close both the pidfd and the
     * socket. Returns true on success.
     */
    public static boolean sendPidfd(String socketPath, int pid) {
        try (Arena arena = Arena.ofConfined()) {
            // pidfd_open(pid, 0)
            long pidfd = Libc.syscall(Constants.NR_pidfd_open, pid, 0, 0L, 0L, 0L);
            if (pidfd < 0) {
                Logger.warn("pidfd_open(" + pid + "): " + Libc.strerror(Libc.errno()));
                return false;
            }
            int fd = (int) pidfd;
            try {
                int sock = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
                if (sock < 0) {
                    Logger.warn("socket for pidfd-socket: " + Libc.strerror(Libc.errno()));
                    return false;
                }
                try {
                    if (PosixIO.connectUnix(arena, sock, socketPath) < 0) {
                        Logger.warn("connect " + socketPath + ": " + Libc.strerror(Libc.errno()));
                        return false;
                    }
                    boolean ok = ScmRights.sendFd(sock, fd, (byte) 0);
                    if (ok) {
                        Logger.debug("pidfd for pid " + pid + " sent to " + socketPath);
                    }
                    return ok;
                } finally {
                    PosixIO.close(sock);
                }
            } finally {
                PosixIO.close(fd);
            }
        }
    }
}
