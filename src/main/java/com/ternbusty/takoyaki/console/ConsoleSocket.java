package com.ternbusty.takoyaki.console;

import com.ternbusty.takoyaki.ipc.ScmRights;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Allocate a pseudo-terminal pair, send the master fd to the caller's console socket,
 * and wire the slave fd to stdin/stdout/stderr of the container init.
 *
 * runc/youki do the same: when --console-socket is given the runtime connects to that
 * AF_UNIX path and ships back the pty master so the parent (containerd-shim, ctr, etc.)
 * can attach to it.
 */
public final class ConsoleSocket {
    private ConsoleSocket() {}

    public static final class PtyPair {
        public final int master;
        public final int slave;
        public PtyPair(int master, int slave) { this.master = master; this.slave = slave; }
    }

    public static PtyPair openPty() {
        try (Arena arena = Arena.ofConfined()) {
            int master = NativeH.posix_openpt(Constants.O_RDWR);
            if (master < 0) {
                Logger.warn("posix_openpt failed: " + Libc.strerror(Libc.errno()));
                return null;
            }
            if (NativeH.grantpt(master) != 0) {
                Logger.warn("grantpt failed: " + Libc.strerror(Libc.errno()));
                PosixIO.close(master);
                return null;
            }
            if (NativeH.unlockpt(master) != 0) {
                Logger.warn("unlockpt failed: " + Libc.strerror(Libc.errno()));
                PosixIO.close(master);
                return null;
            }
            MemorySegment nameBuf = arena.allocate(64);
            if (NativeH.ptsname_r(master, nameBuf, 64L) != 0) {
                Logger.warn("ptsname_r failed: " + Libc.strerror(Libc.errno()));
                PosixIO.close(master);
                return null;
            }
            String slaveName = nameBuf.getString(0);
            int slave = PosixIO.open(arena, slaveName, Constants.O_RDWR, 0);
            if (slave < 0) {
                Logger.warn("open " + slaveName + " failed: " + Libc.strerror(Libc.errno()));
                PosixIO.close(master);
                return null;
            }
            return new PtyPair(master, slave);
        } catch (Throwable t) {
            Logger.warn("openPty error: " + t.getMessage());
            return null;
        }
    }

    /**
     * Connect to the console socket at the given path and return the connected fd.
     * Returns -1 on failure.
     *
     * This must be called BEFORE pivot_root while the host filesystem (and the
     * socket path on it) is still reachable. The returned fd stays valid across
     * pivot_root and can be passed to {@link #sendMasterVia} afterwards.
     */
    public static int connectTo(String consoleSocketPath) {
        try (Arena arena = Arena.ofConfined()) {
            int sock = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
            if (sock < 0) return -1;
            if (PosixIO.connectUnix(arena, sock, consoleSocketPath) < 0) {
                Logger.warn("connect " + consoleSocketPath + ": " + Libc.strerror(Libc.errno()));
                PosixIO.close(sock);
                return -1;
            }
            Logger.debug("connected to console socket " + consoleSocketPath);
            return sock;
        }
    }

    /**
     * Send the pty master fd over an already-connected console socket.
     * The caller is responsible for closing {@code sockFd} afterwards.
     */
    public static boolean sendMasterVia(int sockFd, int masterFd) {
        boolean ok = ScmRights.sendFd(sockFd, masterFd, (byte) 0);
        if (ok) Logger.debug("pty master sent via console socket fd " + sockFd);
        return ok;
    }

    public static boolean sendMasterTo(String consoleSocketPath, int masterFd) {
        int sock = connectTo(consoleSocketPath);
        if (sock < 0) return false;
        try {
            return sendMasterVia(sock, masterFd);
        } finally {
            PosixIO.close(sock);
        }
    }

    /**
     * Set the terminal window size on the given pty fd. Must be called before
     * wireStdio so the slave inherits the size. struct winsize is {rows, cols,
     * xpixel, ypixel} = 4 unsigned shorts = 8 bytes.
     */
    public static void setWinsize(int fd, int rows, int cols) {
        if (rows <= 0 && cols <= 0) return;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ws = arena.allocate(8);
            ws.set(java.lang.foreign.ValueLayout.JAVA_SHORT, 0, (short) rows);
            ws.set(java.lang.foreign.ValueLayout.JAVA_SHORT, 2, (short) cols);
            ws.set(java.lang.foreign.ValueLayout.JAVA_SHORT, 4, (short) 0);
            ws.set(java.lang.foreign.ValueLayout.JAVA_SHORT, 6, (short) 0);
            if (Libc.ioctl(fd, Constants.TIOCSWINSZ, ws) != 0) {
                Logger.warn("TIOCSWINSZ failed: " + Libc.strerror(Libc.errno()));
            }
        }
    }

    /** Replace stdin/stdout/stderr with the slave fd and become the controlling tty. */
    public static void wireStdio(int slaveFd) {
        try {
            // setsid creates a new session and detaches from the current controlling tty.
            NativeH.setsid();
            // Make the slave the controlling terminal for this session. Without
            // TIOCSCTTY the slave is just an open fd, not the controlling tty, so
            // `tty` / `stty size` and job control would not work.
            if (Libc.ioctl(slaveFd, Constants.TIOCSCTTY, MemorySegment.NULL) != 0) {
                Logger.warn("TIOCSCTTY failed: " + Libc.strerror(Libc.errno()));
            }
            NativeH.dup2(slaveFd, 0);
            NativeH.dup2(slaveFd, 1);
            NativeH.dup2(slaveFd, 2);
            if (slaveFd > 2) PosixIO.close(slaveFd);
            Logger.debug("stdio wired to pty slave");
        } catch (Throwable t) {
            Logger.warn("wireStdio error: " + t.getMessage());
        }
    }
}
