package com.ternbusty.takoyaki.console;

import com.ternbusty.takoyaki.ipc.ScmRights;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import com.ternbusty.takoyaki.syscall.posix.PosixH;

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
            int master = PosixH.posix_openpt(Constants.O_RDWR);
            if (master < 0) {
                Logger.warn("posix_openpt failed: " + Libc.strerror(Libc.errno()));
                return null;
            }
            if (PosixH.grantpt(master) != 0) {
                Logger.warn("grantpt failed: " + Libc.strerror(Libc.errno()));
                PosixIO.close(master);
                return null;
            }
            if (PosixH.unlockpt(master) != 0) {
                Logger.warn("unlockpt failed: " + Libc.strerror(Libc.errno()));
                PosixIO.close(master);
                return null;
            }
            MemorySegment nameBuf = arena.allocate(64);
            if (PosixH.ptsname_r(master, nameBuf, 64L) != 0) {
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

    public static boolean sendMasterTo(String consoleSocketPath, int masterFd) {
        try (Arena arena = Arena.ofConfined()) {
            int sock = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
            if (sock < 0) return false;
            try {
                if (PosixIO.connectUnix(arena, sock, consoleSocketPath) < 0) {
                    Logger.warn("connect " + consoleSocketPath + ": " + Libc.strerror(Libc.errno()));
                    return false;
                }
                boolean ok = ScmRights.sendFd(sock, masterFd, (byte) 0);
                if (ok) Logger.debug("pty master sent to " + consoleSocketPath);
                return ok;
            } finally {
                PosixIO.close(sock);
            }
        }
    }

    /** Replace stdin/stdout/stderr with the slave fd and become the controlling tty. */
    public static void wireStdio(int slaveFd) {
        try {
            // setsid creates a new session and detaches from the current controlling tty.
            PosixH.setsid();
            PosixH.dup2(slaveFd, 0);
            PosixH.dup2(slaveFd, 1);
            PosixH.dup2(slaveFd, 2);
            if (slaveFd > 2) PosixIO.close(slaveFd);
            Logger.debug("stdio wired to pty slave");
        } catch (Throwable t) {
            Logger.warn("wireStdio error: " + t.getMessage());
        }
    }
}
