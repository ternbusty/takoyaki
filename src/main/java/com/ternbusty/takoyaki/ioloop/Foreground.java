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
 * Foreground supervision for run/exec, mirroring runc's concurrent
 * architecture: while waiting for the container process to exit, the PTY
 * I/O relay and the signal forwarder (terminal resize + signal delivery to
 * the container) run as concurrent virtual threads under one
 * {@link StructuredTaskScope} — the Java equivalent of runc's goroutines
 * in {@code tty.go} / {@code signals.go} and kontainer-runtime's
 * coroutines in {@code Foreground.kt}.
 *
 * @see IoLoop
 * @see SignalRelay
 */
public final class Foreground {
    private Foreground() {}

    /**
     * Supervise a foreground container: relay PTY I/O, forward signals,
     * and wait for the container process to exit.
     *
     * @param masterFd PTY master to relay to our stdio, or -1 when the
     *   container inherits stdio directly (terminal=false)
     * @param targetPid the container process to supervise
     * @return the container process's exit code
     */
    @SuppressWarnings("preview")
    public static int supervise(int masterFd, int targetPid) {
        try (var io = IoLoop.create();
             var sigRelay = SignalRelay.install()) {
            io.startDriver();
            return runScoped(io, sigRelay, masterFd, targetPid);
        }
    }

    @SuppressWarnings("preview")
    private static int runScoped(IoLoop io, SignalRelay sigRelay,
                                 int masterFd, int targetPid) {
        try (var scope = StructuredTaskScope.open(
                Joiner.awaitAll(),
                cf -> cf.withTimeout(Duration.ofHours(24)))) {

            // PTY relay: two virtual threads for bidirectional copy.
            var relayTask = (masterFd >= 0)
                    ? scope.fork(() -> { relayPtyIO(io, masterFd); return null; })
                    : null;

            // Signal forwarding: SIGWINCH → resize, others → kill(targetPid).
            var sigTask = (sigRelay != null)
                    ? scope.fork(() -> {
                        sigRelay.drainAndForward(io, targetPid, masterFd);
                        return null;
                    })
                    : null;

            // Process exit: wait via pidfd or fallback polling.
            var exitTask = scope.fork(() -> awaitProcessExit(io, targetPid));

            scope.join();
            return exitTask.get();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return 1;
        }
    }

    /**
     * Wait for {@code pid} to exit.  Uses {@code pidfd_open(2)} so the wait
     * is a plain readable-fd event on the IoLoop (like kontainer-runtime's
     * approach).  Falls back to {@code waitpid(WNOHANG)} polling on kernels
     * without pidfd ({@literal <} 5.3).
     */
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

    /** Relay PTY master ↔ stdio until the master closes. */
    private static void relayPtyIO(IoLoop io, int masterFd) {
        IoLoop.setNonBlocking(masterFd);
        IoLoop.setNonBlocking(0); // stdin
        IoLoop.setNonBlocking(1); // stdout
        try (var scope = StructuredTaskScope.open(
                Joiner.awaitAll())) {

            // stdin → master
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

            // master → stdout
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

    /**
     * Write all {@code len} bytes from {@code buf} to a non-blocking
     * {@code fd}, suspending on the IoLoop when the kernel buffer is full.
     */
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

    /** Reap a child and decode its status; returns 0 if not our child. */
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

    /** Non-blocking reap attempt; returns -1 if the child is still running. */
    private static int tryReapChild(int pid) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment status = arena.allocate(ValueLayout.JAVA_INT);
            int rc = Libc.waitpid(pid, status, 1 /* WNOHANG */);
            if (rc == pid) {
                return decodeStatus(status.get(ValueLayout.JAVA_INT, 0));
            }
            if (rc < 0 && Libc.kill(pid, 0) != 0) {
                return 0; // process gone, no longer our child
            }
        }
        return -1;
    }

    private static int decodeStatus(int s) {
        if ((s & 0x7f) == 0) return (s >> 8) & 0xff;
        return 128 + (s & 0x7f);
    }
}
