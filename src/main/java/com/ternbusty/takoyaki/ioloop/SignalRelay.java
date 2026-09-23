package com.ternbusty.takoyaki.ioloop;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Signal forwarding for foreground mode, mirroring runc's {@code signals.go}
 * and kontainer-runtime's {@code Signals.kt}.
 *
 * <p>Uses the self-pipe trick: {@link sun.misc.Signal} handlers write the
 * signal number into a pipe.  The read end is watched via {@link IoLoop} on a
 * virtual thread, which dispatches SIGWINCH as a PTY resize and forwards
 * everything else to the container process.
 *
 * <p>{@code sun.misc.Signal} is used instead of raw {@code sigaction(2)} via
 * FFM because SubstrateVM's GC threads start before {@code main()} with an
 * empty signal mask — process-directed signals may be delivered to them.
 * {@code sun.misc.Signal} integrates with the VM's own signal chaining and
 * avoids that problem.
 */
@SuppressWarnings("removal") // sun.misc.Signal is supported on SubstrateVM
public final class SignalRelay implements AutoCloseable {

    private static final int[] FORWARDED = {
        Constants.SIGWINCH, Constants.SIGTERM, Constants.SIGINT,
        Constants.SIGQUIT, Constants.SIGHUP, Constants.SIGUSR1,
        Constants.SIGUSR2,
    };

    private final int readFd;
    private final int writeFd;

    private SignalRelay(int readFd, int writeFd) {
        this.readFd = readFd;
        this.writeFd = writeFd;
    }

    /** The pipe read-end fd, to be watched via {@link IoLoop#awaitReadable}. */
    public int readFd() { return readFd; }

    /**
     * Create the self-pipe and install signal handlers for all forwarded
     * signals.
     *
     * @return the relay, or {@code null} on failure
     */
    public static SignalRelay install() {
        try (var arena = Arena.ofConfined()) {
            MemorySegment fds = arena.allocate(ValueLayout.JAVA_INT, 2);
            if (NativeH.pipe(fds) != 0) {
                Logger.warn("signal relay: pipe() failed (errno="
                        + Libc.errno() + ")");
                return null;
            }
            int readFd  = fds.getAtIndex(ValueLayout.JAVA_INT, 0);
            int writeFd = fds.getAtIndex(ValueLayout.JAVA_INT, 1);
            IoLoop.setNonBlocking(readFd);
            IoLoop.setNonBlocking(writeFd);

            var relay = new SignalRelay(readFd, writeFd);

            for (int sig : FORWARDED) {
                String name = signalName(sig);
                if (name == null) continue;
                try {
                    sun.misc.Signal.handle(
                            new sun.misc.Signal(name),
                            s -> relay.onSignal(sig));
                } catch (IllegalArgumentException e) {
                    // Can't handle this signal (e.g. SIGKILL) — skip.
                    Logger.debug("signal relay: cannot handle " + name
                            + ": " + e.getMessage());
                }
            }

            Logger.debug("signal relay installed (pipe read fd=" + readFd + ")");
            return relay;
        }
    }

    /**
     * Read pending signal numbers from the pipe and dispatch them:
     * SIGWINCH resizes the PTY master, everything else is forwarded to
     * {@code targetPid}.
     *
     * <p>Called in a loop from a virtual thread suspended on
     * {@link IoLoop#awaitReadable}.
     */
    public void drainAndForward(IoLoop io, int targetPid, int masterFd) {
        if (masterFd >= 0) resizePty(masterFd);
        try (var arena = Arena.ofConfined()) {
            byte[] buf = new byte[64];
            while (!Thread.currentThread().isInterrupted()) {
                io.awaitReadable(readFd);
                long n = PosixIO.read(arena, readFd, buf);
                if (n <= 0) break;
                for (int i = 0; i < (int) n; i++) {
                    int sig = buf[i] & 0xff;
                    if (sig == Constants.SIGWINCH) {
                        if (masterFd >= 0) resizePty(masterFd);
                    } else {
                        Logger.debug("forwarding signal " + sig
                                + " to " + targetPid);
                        Libc.kill(targetPid, sig);
                    }
                }
            }
        }
    }

    /** Signal handler callback — write the signal number into the pipe. */
    private void onSignal(int signo) {
        // write(2) on a non-blocking pipe is async-signal-safe on Linux.
        // If the pipe is full, the signal is silently dropped (matches
        // Go's buffered signal channel semantics).
        try (var arena = Arena.ofConfined()) {
            PosixIO.write(arena, writeFd, new byte[]{(byte) signo});
        } catch (Exception ignored) {
            // Cannot throw from a signal handler context.
        }
    }

    @Override
    public void close() {
        for (int sig : FORWARDED) {
            String name = signalName(sig);
            if (name == null) continue;
            try {
                sun.misc.Signal.handle(
                        new sun.misc.Signal(name),
                        sun.misc.SignalHandler.SIG_DFL);
            } catch (IllegalArgumentException ignored) {}
        }
        PosixIO.close(writeFd);
        PosixIO.close(readFd);
    }

    /** Copy the host terminal's window size onto the PTY master. */
    private static void resizePty(int masterFd) {
        try (var arena = Arena.ofConfined()) {
            // Read winsize from stdin, write to master.
            // struct winsize { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; }
            MemorySegment ws = arena.allocate(8);
            // TIOCGWINSZ = 0x5413
            if (Libc.ioctl(0, 0x5413, ws) == 0) {
                Libc.ioctl(masterFd, 0x5414 /* TIOCSWINSZ */, ws);
            }
        }
    }

    /** Map signal number to the name that {@code sun.misc.Signal} expects. */
    private static String signalName(int sig) {
        if (sig == Constants.SIGWINCH) return "WINCH";
        if (sig == Constants.SIGTERM)  return "TERM";
        if (sig == Constants.SIGINT)   return "INT";
        if (sig == Constants.SIGQUIT)  return "QUIT";
        if (sig == Constants.SIGHUP)   return "HUP";
        if (sig == Constants.SIGUSR1)  return "USR1";
        if (sig == Constants.SIGUSR2)  return "USR2";
        return null;
    }
}
