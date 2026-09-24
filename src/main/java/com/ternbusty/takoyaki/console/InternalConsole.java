package com.ternbusty.takoyaki.console;

import com.ternbusty.takoyaki.ioloop.IoLoop;
import com.ternbusty.takoyaki.ipc.ScmRights;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Internal PTY proxy for foreground {@code runc run} and {@code runc exec -t}
 * when no external {@code --console-socket} is given. The container side
 * opens the pty and sends the master fd back via SCM_RIGHTS; the I/O between
 * the master and the caller's stdin/stdout is then relayed by
 * {@link com.ternbusty.takoyaki.ioloop.Foreground}.
 *
 * <p>For run, a unix socket is bound at a temporary path in the bundle. For
 * exec, a pre-connected socketpair is used instead because the exec process
 * has already entered the container mount namespace (so a host path is
 * unreachable).
 *
 * <p>Nothing here waits on another thread. The runtime connects to the socket
 * itself before starting the init, and the init sends the master (or gives
 * up and closes its end) before it reports ready, so once create has
 * returned the master is either queued on the socket or never coming.
 */
public final class InternalConsole {
    private final String socketPath;
    private int listenFd = -1;
    private int masterFd = -1;

    private InternalConsole(String socketPath) {
        this.socketPath = socketPath;
    }

    /** Console socket path that should be passed to CreateCommand. */
    public String socketPath() { return socketPath; }

    /** The PTY master fd received via SCM_RIGHTS, or -1 if none was received. */
    public int masterFd() { return masterFd; }

    /**
     * Create the internal console socket for foreground {@code runc run}: a
     * non-blocking unix listener at a temporary path in the bundle. Call this
     * before the container init starts, then {@link #receiveMaster()} after
     * create has returned.
     *
     * @return the console, or null if the socket could not be set up
     */
    public static InternalConsole listenForRun(String bundlePath) {
        String path = bundlePath + "/internal-console.sock";
        // Remove stale socket from a previous run (unlink is idempotent).
        try { Files.deleteIfExists(Path.of(path)); } catch (IOException ignored) {}
        InternalConsole console = new InternalConsole(path);
        try (Arena arena = Arena.ofConfined()) {
            int fd = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
            if (fd < 0) {
                Logger.warn("internal console: socket failed: " + Libc.strerror(Libc.errno()));
                return null;
            }
            console.listenFd = fd;
            if (PosixIO.bindUnix(arena, fd, path) < 0) {
                Logger.warn("internal console: bind " + path + " failed: " + Libc.strerror(Libc.errno()));
                console.stop();
                return null;
            }
            if (PosixIO.listen(fd, 1) < 0) {
                Logger.warn("internal console: listen failed: " + Libc.strerror(Libc.errno()));
                console.stop();
                return null;
            }
            IoLoop.setNonBlocking(fd);
        }
        Logger.debug("internal console: listening on " + path);
        return console;
    }

    /**
     * Take the PTY master fd the init sent, without blocking. Must be called
     * after create has returned; a missing connection or message means the
     * init could not set up a pty.
     *
     * @return the master fd, or -1
     */
    public int receiveMaster() {
        if (listenFd < 0) return -1;
        int connFd = PosixIO.accept(listenFd);
        PosixIO.close(listenFd);
        listenFd = -1;
        if (connFd < 0) {
            Logger.warn("internal console: no connection from init: " + Libc.strerror(Libc.errno()));
            return -1;
        }
        IoLoop.setNonBlocking(connFd);
        int fd = ScmRights.recvFd(connFd);
        PosixIO.close(connFd);
        if (fd < 0) {
            Logger.warn("internal console: init did not send a pty master");
            return -1;
        }
        clearONLCR(fd);
        Logger.debug("internal console: received master fd " + fd);
        masterFd = fd;
        return fd;
    }

    /**
     * Receive the PTY master fd from a pre-connected socketpair (exec path).
     * Blocks until the fd arrives or the peer closes; the caller must already
     * have closed its copy of the peer end.
     */
    public static int receiveMasterFromSocket(int sockFd) {
        int fd = ScmRights.recvFd(sockFd);
        if (fd >= 0) {
            clearONLCR(fd);
            Logger.debug("internal console (exec): received master fd " + fd);
        }
        return fd;
    }

    /**
     * Clear the ONLCR flag on a PTY master fd so that output newlines are
     * passed through verbatim instead of being converted to CR+LF. This
     * matches runc's {@code console.ClearONLCR()} and is essential for bats
     * test output comparisons.
     */
    public static void clearONLCR(int fd) {
        try (Arena arena = Arena.ofConfined()) {
            // struct termios (kernel version): c_iflag(4) c_oflag(4) c_cflag(4)
            // c_lflag(4) c_line(1) c_cc[19] = 36 bytes. Allocate 64 for safety.
            MemorySegment termios = arena.allocate(64);
            if (Libc.ioctl(fd, Constants.TCGETS, termios) != 0) {
                Logger.debug("clearONLCR: TCGETS failed: " + Libc.strerror(Libc.errno()));
                return;
            }
            int oflag = termios.get(ValueLayout.JAVA_INT, 4);
            oflag &= ~Constants.ONLCR;
            termios.set(ValueLayout.JAVA_INT, 4, oflag);
            if (Libc.ioctl(fd, Constants.TCSETS, termios) != 0) {
                Logger.debug("clearONLCR: TCSETS failed: " + Libc.strerror(Libc.errno()));
            }
        }
    }

    /** Clean up: close the listener and the master fd, remove the socket file. */
    public void stop() {
        if (listenFd >= 0) {
            PosixIO.close(listenFd);
            listenFd = -1;
        }
        if (masterFd >= 0) {
            PosixIO.close(masterFd);
            masterFd = -1;
        }
        try { Files.deleteIfExists(Path.of(socketPath)); } catch (IOException ignored) {}
    }
}
