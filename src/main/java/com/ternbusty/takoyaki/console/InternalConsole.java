package com.ternbusty.takoyaki.console;

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
 * when no external {@code --console-socket} is given. Creates a temporary unix
 * socket, accepts one connection from the container init (which sends the PTY
 * master fd via SCM_RIGHTS), then copies I/O between the master and the
 * caller's stdin/stdout until the master closes (container exits).
 *
 * <p>For exec, a pre-connected socketpair is used instead of a path-based
 * socket because the exec process has already entered the container mount
 * namespace (so a host path is unreachable).
 */
public final class InternalConsole {
    private final String socketPath;
    private volatile int masterFd = -1;
    private volatile boolean stopped;
    private Thread listenerThread;
    private Thread ioThread;

    private InternalConsole(String socketPath) {
        this.socketPath = socketPath;
    }

    /** Console socket path that should be passed to CreateCommand. */
    public String socketPath() { return socketPath; }

    /**
     * Create an internal console socket for foreground {@code runc run}. The
     * returned object owns a unix listener socket at a temporary path; call
     * {@link #startListening()} before the container init starts so the socket
     * is ready.
     */
    public static InternalConsole createForRun(String bundlePath) {
        String path = bundlePath + "/internal-console.sock";
        // Remove stale socket from a previous run (unlink is idempotent).
        try { Files.deleteIfExists(Path.of(path)); } catch (IOException ignored) {}
        return new InternalConsole(path);
    }

    /**
     * Start a thread that listens on the socket, accepts one connection, and
     * receives the PTY master fd via SCM_RIGHTS. The master fd is stashed for
     * {@link #startIOCopy()} to pick up.
     */
    public void startListening() {
        listenerThread = new Thread(() -> {
            try (Arena arena = Arena.ofConfined()) {
                int listenFd = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
                if (listenFd < 0) {
                    Logger.warn("internal console: socket failed: " + Libc.strerror(Libc.errno()));
                    return;
                }
                if (PosixIO.bindUnix(arena, listenFd, socketPath) < 0) {
                    Logger.warn("internal console: bind " + socketPath + " failed: "
                            + Libc.strerror(Libc.errno()));
                    PosixIO.close(listenFd);
                    return;
                }
                if (PosixIO.listen(listenFd, 1) < 0) {
                    Logger.warn("internal console: listen failed: " + Libc.strerror(Libc.errno()));
                    PosixIO.close(listenFd);
                    return;
                }
                Logger.debug("internal console: waiting for connection on " + socketPath);
                int connFd = PosixIO.accept(listenFd);
                PosixIO.close(listenFd);
                if (connFd < 0) {
                    if (!stopped) {
                        Logger.warn("internal console: accept failed: " + Libc.strerror(Libc.errno()));
                    }
                    return;
                }
                masterFd = ScmRights.recvFd(connFd);
                PosixIO.close(connFd);
                if (masterFd >= 0) {
                    clearONLCR(masterFd);
                    Logger.debug("internal console: received master fd " + masterFd);
                } else {
                    Logger.warn("internal console: failed to receive master fd");
                }
            }
        }, "internal-console-listener");
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    /** Wait for the listener thread to complete (connection established). */
    public boolean awaitMaster(long timeoutMs) {
        if (listenerThread == null) return false;
        try { listenerThread.join(timeoutMs); } catch (InterruptedException ignored) {}
        return masterFd >= 0;
    }

    /**
     * Receive the PTY master fd from a pre-connected socketpair (exec path).
     * Blocks until the fd arrives or the peer closes.
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
     * Start I/O copying between the PTY master and the caller's stdin/stdout.
     * Returns immediately; copying runs in background threads. Call
     * {@link #stop()} after the container exits to clean up.
     */
    public void startIOCopy() {
        if (masterFd < 0) return;
        ioThread = startIOCopyForFd(masterFd);
    }

    /**
     * Start I/O copying for a given master fd (used by both run and exec paths).
     */
    public static Thread startIOCopyForFd(int masterFd) {
        // master → stdout thread (the important direction for bats tests).
        Thread reader = new Thread(() -> {
            try (Arena arena = Arena.ofConfined()) {
                byte[] buf = new byte[8192];
                while (true) {
                    long n = PosixIO.read(arena, masterFd, buf);
                    if (n <= 0) break;
                    System.out.write(buf, 0, (int) n);
                    System.out.flush();
                }
            } catch (Exception ignored) {}
        }, "pty-to-stdout");
        reader.setDaemon(true);
        reader.start();

        // stdin → master thread (for interactive use).
        Thread writer = new Thread(() -> {
            try (Arena arena = Arena.ofConfined()) {
                byte[] buf = new byte[4096];
                while (true) {
                    int n = System.in.read(buf);
                    if (n <= 0) break;
                    byte[] chunk = n == buf.length ? buf : java.util.Arrays.copyOf(buf, n);
                    PosixIO.write(arena, masterFd, chunk);
                }
            } catch (Exception ignored) {}
        }, "stdin-to-pty");
        writer.setDaemon(true);
        writer.start();

        return reader;
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

    /** Clean up: wait for I/O threads to drain, close master fd, remove socket file. */
    public void stop() {
        stopped = true;
        // Let the reader thread drain remaining PTY data before closing the fd.
        // Without this, a race between waitForChild returning and the reader
        // reaching EOF can lose the last chunk of container output.
        if (ioThread != null) {
            try { ioThread.join(5_000); } catch (InterruptedException ignored) {}
        }
        if (masterFd >= 0) {
            PosixIO.close(masterFd);
            masterFd = -1;
        }
        if (socketPath != null) {
            try { Files.deleteIfExists(Path.of(socketPath)); } catch (IOException ignored) {}
        }
    }
}
