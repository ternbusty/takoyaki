package com.ternbusty.takoyaki.ipc;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.lang.foreign.Arena;

import static com.ternbusty.takoyaki.syscall.Constants.AF_UNIX;
import static com.ternbusty.takoyaki.syscall.Constants.SOCK_STREAM;

public final class NotifySocket {
    private NotifySocket() {}

    /** Canonical notify socket path for a container. Single owner of the naming scheme. */
    public static String pathFor(String containerId) {
        return "/tmp/takoyaki-" + containerId + ".sock";
    }

    public static int createListener(String socketPath) {
        try (Arena arena = Arena.ofConfined()) {
            int fd = PosixIO.socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) throw new RuntimeException("socket: " + Libc.strerror(Libc.errno()));
            PosixIO.unlink(arena, socketPath);
            if (PosixIO.bindUnix(arena, fd, socketPath) < 0) {
                int e = Libc.errno();
                PosixIO.close(fd);
                throw new RuntimeException("bind " + socketPath + ": " + Libc.strerror(e));
            }
            if (PosixIO.listen(fd, 1) < 0) {
                int e = Libc.errno();
                PosixIO.close(fd);
                throw new RuntimeException("listen: " + Libc.strerror(e));
            }
            Logger.debug("notify listener bound on " + socketPath + " fd=" + fd);
            return fd;
        }
    }

    public static void waitForStart(int listenFd) {
        int cs = PosixIO.accept(listenFd);
        if (cs < 0) throw new RuntimeException("accept: " + Libc.strerror(Libc.errno()));
        try (Arena arena = Arena.ofConfined()) {
            byte[] buf = new byte[256];
            long n = PosixIO.recv(arena, cs, buf, 0);
            if (n < 0) throw new RuntimeException("recv: " + Libc.strerror(Libc.errno()));
            Logger.debug("notify listener received: " + new String(buf, 0, (int) Math.max(0, n)));
        } finally {
            PosixIO.close(cs);
        }
    }

    public static void sendStart(String socketPath) {
        try (Arena arena = Arena.ofConfined()) {
            int fd = PosixIO.socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) throw new RuntimeException("socket: " + Libc.strerror(Libc.errno()));
            try {
                if (PosixIO.connectUnix(arena, fd, socketPath) < 0) {
                    throw new RuntimeException("connect " + socketPath + ": " + Libc.strerror(Libc.errno()));
                }
                byte[] msg = "start container".getBytes();
                long n = PosixIO.send(arena, fd, msg, 0);
                if (n < 0) throw new RuntimeException("send: " + Libc.strerror(Libc.errno()));
                Logger.debug("notify sent start to " + socketPath);
            } finally {
                PosixIO.close(fd);
            }
        }
    }
}
