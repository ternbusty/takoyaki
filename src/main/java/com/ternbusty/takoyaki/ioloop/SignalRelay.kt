package com.ternbusty.takoyaki.ioloop

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.syscall.gen.NativeH
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

/**
 * Signal forwarding for foreground mode, mirroring runc's `signals.go`
 * and kontainer-runtime's `Signals.kt`.
 *
 * Uses the self-pipe trick: [sun.misc.Signal] handlers write the
 * signal number into a pipe.  The read end is watched via [IoLoop] on a
 * virtual thread, which dispatches SIGWINCH as a PTY resize and forwards
 * everything else to the container process.
 *
 * `sun.misc.Signal` is used instead of raw `sigaction(2)` via
 * FFM because SubstrateVM's GC threads start before `main()` with an
 * empty signal mask -- process-directed signals may be delivered to them.
 * `sun.misc.Signal` integrates with the VM's own signal chaining and
 * avoids that problem.
 */
@Suppress("removal") // sun.misc.Signal is supported on SubstrateVM
class SignalRelay private constructor(
    val readFd: Int,
    private val writeFd: Int,
) : AutoCloseable {

    /**
     * Read pending signal numbers from the pipe and dispatch them:
     * SIGWINCH resizes the PTY master, everything else is forwarded to
     * [targetPid].
     *
     * Called in a loop from a virtual thread suspended on
     * [IoLoop.awaitReadable].
     */
    fun drainAndForward(io: IoLoop, targetPid: Int, masterFd: Int) {
        if (masterFd >= 0) resizePty(masterFd)
        Arena.ofConfined().use { arena ->
            val buf = ByteArray(64)
            while (!Thread.currentThread().isInterrupted) {
                io.awaitReadable(readFd)
                val n = PosixIO.read(arena, readFd, buf)
                if (n <= 0) break
                for (i in 0 until n.toInt()) {
                    val sig = buf[i].toInt() and 0xff
                    if (sig == Constants.SIGWINCH) {
                        if (masterFd >= 0) resizePty(masterFd)
                    } else {
                        Logger.debug("forwarding signal $sig to $targetPid")
                        Libc.kill(targetPid, sig)
                    }
                }
            }
        }
    }

    /** Signal handler callback -- write the signal number into the pipe. */
    private fun onSignal(signo: Int) {
        // write(2) on a non-blocking pipe is async-signal-safe on Linux.
        // If the pipe is full, the signal is silently dropped (matches
        // Go's buffered signal channel semantics).
        try {
            Arena.ofConfined().use { arena ->
                PosixIO.write(arena, writeFd, byteArrayOf(signo.toByte()))
            }
        } catch (_: Exception) {
            // Cannot throw from a signal handler context.
        }
    }

    override fun close() {
        for (sig in FORWARDED) {
            val name = signalName(sig) ?: continue
            try {
                sun.misc.Signal.handle(
                    sun.misc.Signal(name),
                    sun.misc.SignalHandler.SIG_DFL,
                )
            } catch (_: IllegalArgumentException) {}
        }
        PosixIO.close(writeFd)
        PosixIO.close(readFd)
    }

    companion object {
        private val FORWARDED = intArrayOf(
            Constants.SIGWINCH, Constants.SIGTERM, Constants.SIGINT,
            Constants.SIGQUIT, Constants.SIGHUP, Constants.SIGUSR1,
            Constants.SIGUSR2,
        )

        /**
         * Create the self-pipe and install signal handlers for all forwarded
         * signals.
         *
         * @return the relay, or null on failure
         */
        fun install(): SignalRelay? {
            Arena.ofConfined().use { arena ->
                val fds = arena.allocate(ValueLayout.JAVA_INT, 2)
                if (NativeH.pipe(fds) != 0) {
                    Logger.warn("signal relay: pipe() failed (errno=${Libc.errno()})")
                    return null
                }
                val readFd = fds.getAtIndex(ValueLayout.JAVA_INT, 0)
                val writeFd = fds.getAtIndex(ValueLayout.JAVA_INT, 1)
                IoLoop.setNonBlocking(readFd)
                IoLoop.setNonBlocking(writeFd)

                val relay = SignalRelay(readFd, writeFd)

                for (sig in FORWARDED) {
                    val name = signalName(sig) ?: continue
                    try {
                        sun.misc.Signal.handle(
                            sun.misc.Signal(name),
                        ) { relay.onSignal(sig) }
                    } catch (e: IllegalArgumentException) {
                        // Can't handle this signal (e.g. SIGKILL) -- skip.
                        Logger.debug("signal relay: cannot handle $name: ${e.message}")
                    }
                }

                Logger.debug("signal relay installed (pipe read fd=$readFd)")
                return relay
            }
        }

        /** Copy the host terminal's window size onto the PTY master. */
        private fun resizePty(masterFd: Int) {
            Arena.ofConfined().use { arena ->
                // Read winsize from stdin, write to master.
                // struct winsize { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; }
                val ws = arena.allocate(8)
                // TIOCGWINSZ = 0x5413
                if (Libc.ioctl(0, 0x5413, ws) == 0) {
                    Libc.ioctl(masterFd, 0x5414 /* TIOCSWINSZ */, ws)
                }
            }
        }

        /** Map signal number to the name that [sun.misc.Signal] expects. */
        private fun signalName(sig: Int): String? = when (sig) {
            Constants.SIGWINCH -> "WINCH"
            Constants.SIGTERM -> "TERM"
            Constants.SIGINT -> "INT"
            Constants.SIGQUIT -> "QUIT"
            Constants.SIGHUP -> "HUP"
            Constants.SIGUSR1 -> "USR1"
            Constants.SIGUSR2 -> "USR2"
            else -> null
        }
    }
}
