package com.ternbusty.takoyaki.ioloop

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.syscall.gen.NativeH
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.time.Duration
import java.util.concurrent.StructuredTaskScope
import java.util.concurrent.StructuredTaskScope.Joiner

/**
 * Foreground supervision for run/exec.  The calling platform thread drives
 * the IoLoop (`epoll_wait` loop) while virtual threads handle PTY
 * relay, signal forwarding, and process exit wait under a
 * [StructuredTaskScope].  No additional platform thread is spawned.
 *
 * @see IoLoop
 * @see SignalRelay
 */
object Foreground {

    /**
     * Supervise a foreground container.  The calling thread runs the IoLoop
     * driver; all I/O tasks run on virtual threads.
     *
     * @param masterFd PTY master fd, or -1 for non-terminal
     * @param targetPid the container process to supervise
     * @return the container process's exit code
     */
    fun supervise(masterFd: Int, targetPid: Int): Int {
        IoLoop.create().use { io ->
            val sigRelay = SignalRelay.install()
            try {
                return runScoped(io, sigRelay, masterFd, targetPid)
            } finally {
                sigRelay?.close()
            }
        }
    }

    private fun runScoped(
        io: IoLoop,
        sigRelay: SignalRelay?,
        masterFd: Int,
        targetPid: Int,
    ): Int {
        try {
            StructuredTaskScope.open(
                Joiner.awaitAll(),
            ) { cf -> cf.withTimeout(Duration.ofHours(24)) }.use { scope ->

                if (masterFd >= 0) {
                    scope.fork { relayPtyIO(io, masterFd); null }
                }
                if (sigRelay != null) {
                    scope.fork {
                        sigRelay.drainAndForward(io, targetPid, masterFd)
                        null
                    }
                }
                val exitTask = scope.fork {
                    val code = awaitProcessExit(io, targetPid)
                    io.shutdown()
                    code
                }

                // The calling thread drives epoll_wait until shutdown.
                io.run()

                scope.join()
                return exitTask.get()
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return 1
        }
    }

    private fun awaitProcessExit(io: IoLoop, pid: Int): Int {
        val pidfd = Libc.syscall(Constants.NR_pidfd_open, pid.toLong(), 0, 0, 0, 0)
        if (pidfd >= 0) {
            try {
                io.awaitReadable(pidfd.toInt())
            } finally {
                PosixIO.close(pidfd.toInt())
            }
            return reapChild(pid)
        }

        Logger.debug("pidfd_open failed (errno=${Libc.errno()}), falling back to WNOHANG polling")
        while (true) {
            val code = tryReapChild(pid)
            if (code >= 0) return code
            try {
                Thread.sleep(100)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return 0
            }
        }
    }

    private fun relayPtyIO(io: IoLoop, masterFd: Int) {
        IoLoop.setNonBlocking(masterFd)
        IoLoop.setNonBlocking(0)
        IoLoop.setNonBlocking(1)
        try {
            StructuredTaskScope.open(Joiner.awaitAll()).use { scope ->

                scope.fork {
                    Arena.ofConfined().use { arena ->
                        val buf = ByteArray(8192)
                        while (!Thread.currentThread().isInterrupted) {
                            io.awaitReadable(0)
                            val n = PosixIO.read(arena, 0, buf)
                            if (n <= 0) break
                            if (!writeAll(io, masterFd, buf, n.toInt())) break
                        }
                    }
                    null
                }

                scope.fork {
                    Arena.ofConfined().use { arena ->
                        val buf = ByteArray(8192)
                        while (!Thread.currentThread().isInterrupted) {
                            io.awaitReadable(masterFd)
                            val n = PosixIO.read(arena, masterFd, buf)
                            if (n <= 0) break
                            if (!writeAll(io, 1, buf, n.toInt())) break
                        }
                    }
                    null
                }

                scope.join()
            }
        } catch (_: InterruptedException) {
        } finally {
            IoLoop.restoreBlocking(masterFd)
            IoLoop.restoreBlocking(0)
            IoLoop.restoreBlocking(1)
        }
    }

    private fun writeAll(io: IoLoop, fd: Int, buf: ByteArray, len: Int): Boolean {
        Arena.ofConfined().use { arena ->
            val seg = arena.allocate(len.toLong())
            MemorySegment.copy(buf, 0, seg, ValueLayout.JAVA_BYTE, 0, len)
            var off = 0L
            while (off < len) {
                val n = NativeH.write(fd, seg.asSlice(off), len.toLong() - off)
                if (n < 0) {
                    val err = Libc.errno()
                    if (err == Constants.EAGAIN) {
                        if (io.isClosed) return false
                        io.awaitWritable(fd)
                        continue
                    }
                    return false
                }
                off += n
            }
        }
        return true
    }

    private fun reapChild(pid: Int): Int {
        Arena.ofConfined().use { arena ->
            val status = arena.allocate(ValueLayout.JAVA_INT)
            val rc = Libc.waitpid(pid, status, 0)
            if (rc == pid) {
                return decodeStatus(status.get(ValueLayout.JAVA_INT, 0))
            }
        }
        return 0
    }

    private fun tryReapChild(pid: Int): Int {
        Arena.ofConfined().use { arena ->
            val status = arena.allocate(ValueLayout.JAVA_INT)
            val rc = Libc.waitpid(pid, status, 1 /* WNOHANG */)
            if (rc == pid) {
                return decodeStatus(status.get(ValueLayout.JAVA_INT, 0))
            }
            if (rc < 0 && Libc.kill(pid, 0) != 0) {
                return 0
            }
        }
        return -1
    }

    private fun decodeStatus(s: Int): Int =
        if ((s and 0x7f) == 0) (s shr 8) and 0xff
        else 128 + (s and 0x7f)
}
