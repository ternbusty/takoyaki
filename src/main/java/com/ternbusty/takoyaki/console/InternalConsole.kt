package com.ternbusty.takoyaki.console

import com.ternbusty.takoyaki.ipc.ScmRights
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout
import java.nio.file.Files
import java.nio.file.Path

/**
 * Internal PTY proxy for foreground `runc run` and `runc exec -t`
 * when no external `--console-socket` is given. Creates a temporary unix
 * socket, accepts one connection from the container init (which sends the PTY
 * master fd via SCM_RIGHTS), then copies I/O between the master and the
 * caller's stdin/stdout until the master closes (container exits).
 *
 * For exec, a pre-connected socketpair is used instead of a path-based
 * socket because the exec process has already entered the container mount
 * namespace (so a host path is unreachable).
 */
class InternalConsole private constructor(
    /** Console socket path that should be passed to CreateCommand. */
    val socketPath: String,
) {
    @Volatile
    private var masterFd: Int = -1

    @Volatile
    private var stopped: Boolean = false

    private var listenerThread: Thread? = null
    private var ioThread: Thread? = null

    companion object {
        /**
         * Create an internal console socket for foreground `runc run`. The
         * returned object owns a unix listener socket at a temporary path; call
         * [startListening] before the container init starts so the socket
         * is ready.
         */
        fun createForRun(bundlePath: String): InternalConsole {
            val path = "$bundlePath/internal-console.sock"
            // Remove stale socket from a previous run (unlink is idempotent).
            try {
                Files.deleteIfExists(Path.of(path))
            } catch (_: IOException) {
            }
            return InternalConsole(path)
        }

        /**
         * Receive the PTY master fd from a pre-connected socketpair (exec path).
         * Blocks until the fd arrives or the peer closes.
         */
        fun receiveMasterFromSocket(sockFd: Int): Int {
            val fd = ScmRights.recvFd(sockFd)
            if (fd >= 0) {
                clearONLCR(fd)
                Logger.debug("internal console (exec): received master fd $fd")
            }
            return fd
        }

        /**
         * Start I/O copying for a given master fd (used by both run and exec paths).
         */
        fun startIOCopyForFd(masterFd: Int): Thread {
            // master -> stdout thread (the important direction for bats tests).
            val reader = Thread({
                try {
                    Arena.ofConfined().use { arena ->
                        val buf = ByteArray(8192)
                        while (true) {
                            val n = PosixIO.read(arena, masterFd, buf)
                            if (n <= 0) break
                            System.out.write(buf, 0, n.toInt())
                            System.out.flush()
                        }
                    }
                } catch (_: Exception) {
                }
            }, "pty-to-stdout")
            reader.isDaemon = true
            reader.start()

            // stdin -> master thread (for interactive use).
            val writer = Thread({
                try {
                    Arena.ofConfined().use { arena ->
                        val buf = ByteArray(4096)
                        while (true) {
                            val n = System.`in`.read(buf)
                            if (n <= 0) break
                            val chunk = if (n == buf.size) buf else buf.copyOf(n)
                            PosixIO.write(arena, masterFd, chunk)
                        }
                    }
                } catch (_: Exception) {
                }
            }, "stdin-to-pty")
            writer.isDaemon = true
            writer.start()

            return reader
        }

        /**
         * Clear the ONLCR flag on a PTY master fd so that output newlines are
         * passed through verbatim instead of being converted to CR+LF. This
         * matches runc's `console.ClearONLCR()` and is essential for bats
         * test output comparisons.
         */
        fun clearONLCR(fd: Int) {
            Arena.ofConfined().use { arena ->
                // struct termios (kernel version): c_iflag(4) c_oflag(4) c_cflag(4)
                // c_lflag(4) c_line(1) c_cc[19] = 36 bytes. Allocate 64 for safety.
                val termios = arena.allocate(64)
                if (Libc.ioctl(fd, Constants.TCGETS, termios) != 0) {
                    Logger.debug("clearONLCR: TCGETS failed: ${Libc.strerror(Libc.errno())}")
                    return
                }
                var oflag = termios.get(ValueLayout.JAVA_INT, 4)
                oflag = oflag and Constants.ONLCR.inv()
                termios.set(ValueLayout.JAVA_INT, 4, oflag)
                if (Libc.ioctl(fd, Constants.TCSETS, termios) != 0) {
                    Logger.debug("clearONLCR: TCSETS failed: ${Libc.strerror(Libc.errno())}")
                }
            }
        }
    }

    /**
     * Start a thread that listens on the socket, accepts one connection, and
     * receives the PTY master fd via SCM_RIGHTS. The master fd is stashed for
     * [startIOCopy] to pick up.
     */
    fun startListening() {
        listenerThread = Thread({
            Arena.ofConfined().use { arena ->
                val listenFd = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0)
                if (listenFd < 0) {
                    Logger.warn("internal console: socket failed: ${Libc.strerror(Libc.errno())}")
                    return@use
                }
                if (PosixIO.bindUnix(arena, listenFd, socketPath) < 0) {
                    Logger.warn(
                        "internal console: bind $socketPath failed: ${Libc.strerror(Libc.errno())}"
                    )
                    PosixIO.close(listenFd)
                    return@use
                }
                if (PosixIO.listen(listenFd, 1) < 0) {
                    Logger.warn("internal console: listen failed: ${Libc.strerror(Libc.errno())}")
                    PosixIO.close(listenFd)
                    return@use
                }
                Logger.debug("internal console: waiting for connection on $socketPath")
                val connFd = PosixIO.accept(listenFd)
                PosixIO.close(listenFd)
                if (connFd < 0) {
                    if (!stopped) {
                        Logger.warn(
                            "internal console: accept failed: ${Libc.strerror(Libc.errno())}"
                        )
                    }
                    return@use
                }
                masterFd = ScmRights.recvFd(connFd)
                PosixIO.close(connFd)
                if (masterFd >= 0) {
                    clearONLCR(masterFd)
                    Logger.debug("internal console: received master fd $masterFd")
                } else {
                    Logger.warn("internal console: failed to receive master fd")
                }
            }
        }, "internal-console-listener").also {
            it.isDaemon = true
            it.start()
        }
    }

    /** Wait for the listener thread to complete (connection established). */
    fun awaitMaster(timeoutMs: Long): Boolean {
        val thread = listenerThread ?: return false
        try {
            thread.join(timeoutMs)
        } catch (_: InterruptedException) {
        }
        return masterFd >= 0
    }

    /**
     * Start I/O copying between the PTY master and the caller's stdin/stdout.
     * Returns immediately; copying runs in background threads. Call
     * [stop] after the container exits to clean up.
     */
    fun startIOCopy() {
        if (masterFd < 0) return
        ioThread = startIOCopyForFd(masterFd)
    }

    /** Clean up: wait for I/O threads to drain, close master fd, remove socket file. */
    fun stop() {
        stopped = true
        // Let the reader thread drain remaining PTY data before closing the fd.
        // Without this, a race between waitForChild returning and the reader
        // reaching EOF can lose the last chunk of container output.
        ioThread?.let {
            try {
                it.join(5_000)
            } catch (_: InterruptedException) {
            }
        }
        if (masterFd >= 0) {
            PosixIO.close(masterFd)
            masterFd = -1
        }
        try {
            Files.deleteIfExists(Path.of(socketPath))
        } catch (_: IOException) {
        }
    }
}
