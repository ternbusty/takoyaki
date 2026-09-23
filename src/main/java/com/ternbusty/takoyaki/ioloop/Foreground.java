package com.ternbusty.takoyaki.ioloop;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Duration;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.StructuredTaskScope.Joiner;

/**
 * Foreground supervision for run/exec.  The calling platform thread drives
 * the IoLoop ({@code epoll_wait} loop) while virtual threads handle PTY
 * relay, signal forwarding, and process exit wait under a
 * {@link StructuredTaskScope}.  No additional platform thread is spawned.
 *
 * @see IoLoop
 * @see SignalRelay
 */
public final class Foreground {
    private Foreground() {}

    /**
     * Supervise a foreground container.  The calling thread runs the IoLoop
     * driver; all I/O tasks run on virtual threads.
     *
     * @param masterFd PTY master fd, or -1 for non-terminal
     * @param targetPid the container process to supervise
     * @return the container process's exit code
     */
    @SuppressWarnings("preview")
    public static int supervise(int masterFd, int targetPid) {
        try (var io = IoLoop.create();
             var sigRelay = SignalRelay.install()) {
            return runScoped(io, sigRelay, masterFd, targetPid);
        }
    }

    @SuppressWarnings("preview")
    private static int runScoped(IoLoop io, SignalRelay sigRelay,
                                 int masterFd, int targetPid) {
        try (var scope = StructuredTaskScope.open(
                Joiner.awaitAll(),
                cf -> cf.withTimeout(Duration.ofHours(24)))) {

            if (masterFd >= 0) {
                scope.fork(() -> { relayPtyIO(io, masterFd); return null; });
            }
            if (sigRelay != null) {
                scope.fork(() -> {
                    sigRelay.drainAndForward(io, targetPid, masterFd);
                    return null;
                });
            }
            var exitTask = scope.fork(() -> {
                int code = awaitProcessExit(io, targetPid);
                io.shutdown();
                return code;
            });

            // The calling thread drives epoll_wait until shutdown.
            io.run();

            scope.join();
            return exitTask.get();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return 1;
        }
    }

    private static int awaitProcessExit(IoLoop io, int pid) {
        long pidfd = Libc.syscall(Constants.NR_pidfd_open, pid, 0, 0, 0, 0);
        if (pidfd >= 0) {
            try {
                io.awaitReadable((int) pidfd);
            } finally {
                PosixIO.close((int) pidfd);
            }
            return reapChild(pid);
        }

        Logger.debug("pidfd_open failed (errno=" + Libc.errno()
                + "), falling back to WNOHANG polling");
        while (true) {
            int code = tryReapChild(pid);
            if (code >= 0) return code;
            try { Thread.sleep(100); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return 0;
            }
        }
    }

    private static void relayPtyIO(IoLoop io, int masterFd) {
        IoLoop.setNonBlocking(masterFd);
        IoLoop.setNonBlocking(0);
        IoLoop.setNonBlocking(1);
        try (var scope = StructuredTaskScope.open(
                Joiner.awaitAll())) {

            scope.fork(() -> {
                try (var arena = Arena.ofConfined()) {
                    byte[] buf = new byte[8192];
                    while (!Thread.currentThread().isInterrupted()) {
                        io.awaitReadable(0);
                        long n = PosixIO.read(arena, 0, buf);
                        if (n <= 0) break;
                        if (!writeAll(io, masterFd, buf, (int) n)) break;
                    }
                }
                return null;
            });

            scope.fork(() -> {
                try (var arena = Arena.ofConfined()) {
                    byte[] buf = new byte[8192];
                    while (!Thread.currentThread().isInterrupted()) {
                        io.awaitReadable(masterFd);
                        long n = PosixIO.read(arena, masterFd, buf);
                        if (n <= 0) break;
                        if (!writeAll(io, 1, buf, (int) n)) break;
                    }
                }
                return null;
            });

            scope.join();
        } catch (InterruptedException ignored) {
        } finally {
            IoLoop.restoreBlocking(masterFd);
            IoLoop.restoreBlocking(0);
            IoLoop.restoreBlocking(1);
        }
    }

    private static boolean writeAll(IoLoop io, int fd, byte[] buf, int len) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(len);
            MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, len);
            long off = 0;
            while (off < len) {
                long n = NativeH.write(fd, seg.asSlice(off), len - off);
                if (n < 0) {
                    int err = Libc.errno();
                    if (err == Constants.EAGAIN) {
                        if (io.isClosed()) return false;
                        io.awaitWritable(fd);
                        continue;
                    }
                    return false;
                }
                off += n;
            }
        }
        return true;
    }

    private static int reapChild(int pid) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment status = arena.allocate(ValueLayout.JAVA_INT);
            int rc = Libc.waitpid(pid, status, 0);
            if (rc == pid) {
                return decodeStatus(status.get(ValueLayout.JAVA_INT, 0));
            }
        }
        return 0;
    }

    private static int tryReapChild(int pid) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment status = arena.allocate(ValueLayout.JAVA_INT);
            int rc = Libc.waitpid(pid, status, 1 /* WNOHANG */);
            if (rc == pid) {
                return decodeStatus(status.get(ValueLayout.JAVA_INT, 0));
            }
            if (rc < 0 && Libc.kill(pid, 0) != 0) {
                return 0;
            }
        }
        return -1;
    }

    private static int decodeStatus(int s) {
        if ((s & 0x7f) == 0) return (s >> 8) & 0xff;
        return 128 + (s & 0x7f);
    }
}
