package com.ternbusty.takoyaki.ioloop

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.syscall.gen.NativeH
import com.ternbusty.takoyaki.syscall.gen.NativeH_3
import com.ternbusty.takoyaki.syscall.gen.epoll_data
import com.ternbusty.takoyaki.syscall.gen.epoll_event
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.LockSupport

/**
 * Epoll-backed I/O loop that suspends virtual threads instead of blocking
 * platform threads.
 *
 * Each [awaitReadable]/[awaitWritable] call parks the (virtual)
 * calling thread.  The caller's platform thread drives the loop via
 * [run], calling `epoll_wait` and unparking waiters as their
 * fds become ready -- no extra thread is spawned.
 *
 * Thread safety: [awaitReadable]/[awaitWritable] may be called
 * from any thread; the waiter map is a [ConcurrentHashMap] and
 * `epoll_ctl` is thread-safe in the kernel.
 */
class IoLoop private constructor(
    private val epfd: Int,
    private val wakeReadFd: Int,
    private val wakeWriteFd: Int,
) : AutoCloseable {

    /** Per-fd waiter slots. */
    private class FdWaiters {
        @Volatile var reader: Thread? = null
        @Volatile var writer: Thread? = null
    }

    private val waiters = ConcurrentHashMap<Int, FdWaiters>()

    @Volatile var isClosed: Boolean = false
        private set

    /**
     * Run the driver loop on the calling thread.  Blocks until
     * [shutdown] is called, then returns.
     */
    fun run() {
        Arena.ofConfined().use { arena ->
            val eventSize = epoll_event.layout().byteSize()
            val events = arena.allocate(eventSize * MAX_EVENTS)
            while (!isClosed) {
                val n = NativeH.epoll_wait(epfd, events, MAX_EVENTS, -1)
                if (n < 0) {
                    if (Libc.errno() == Constants.EINTR) continue
                    if (isClosed) break
                    Logger.debug("ioloop: epoll_wait error errno=${Libc.errno()}")
                    continue
                }
                for (i in 0 until n) {
                    val ev = events.asSlice(i * eventSize, eventSize)
                    val bits = epoll_event.events(ev)
                    val fd = epoll_data.fd(epoll_event.data(ev))

                    if (fd == WAKEUP_FD) continue

                    val w = waiters[fd] ?: continue

                    val hupOrErr = (bits and (Constants.EPOLLHUP or Constants.EPOLLERR)) != 0

                    if ((bits and Constants.EPOLLIN) != 0 || hupOrErr) {
                        val t = w.reader
                        if (t != null) {
                            w.reader = null
                            LockSupport.unpark(t)
                        }
                    }
                    if ((bits and Constants.EPOLLOUT) != 0 || hupOrErr) {
                        val t = w.writer
                        if (t != null) {
                            w.writer = null
                            LockSupport.unpark(t)
                        }
                    }

                    if (w.reader != null || w.writer != null) {
                        arm(fd, w)
                    } else {
                        waiters.remove(fd)
                    }
                }
            }
        }
    }

    /** Park the calling virtual thread until [fd] is readable. */
    fun awaitReadable(fd: Int) {
        awaitEvent(fd, wantWrite = false)
    }

    /** Park the calling virtual thread until [fd] is writable. */
    fun awaitWritable(fd: Int) {
        awaitEvent(fd, wantWrite = true)
    }

    private fun awaitEvent(fd: Int, wantWrite: Boolean) {
        if (isClosed) return
        val w = waiters.computeIfAbsent(fd) { FdWaiters() }
        if (wantWrite) {
            w.writer = Thread.currentThread()
        } else {
            w.reader = Thread.currentThread()
        }
        val rc = arm(fd, w)
        if (rc != 0) {
            if (wantWrite) w.writer = null else w.reader = null
            if (w.reader == null && w.writer == null) waiters.remove(fd)
            if (rc == Constants.EPERM) return
            throw IllegalStateException("epoll_ctl failed for fd=$fd (errno=$rc)")
        }
        // Re-check after registration: shutdown() may have iterated
        // waiters between our first check and here, missing this entry.
        // If shutdown() runs after this check but before park(), its
        // unpark() sets a permit that park() consumes immediately.
        if (isClosed) {
            if (wantWrite) w.writer = null else w.reader = null
            return
        }
        LockSupport.park(this)
    }

    /**
     * (Re-)register [fd] with EPOLLONESHOT and the interest set implied
     * by its current waiters.
     *
     * @return 0 on success, errno on failure
     */
    private fun arm(fd: Int, w: FdWaiters): Int {
        Arena.ofConfined().use { arena ->
            val ev = epoll_event.allocate(arena)
            var interest = Constants.EPOLLONESHOT
            if (w.reader != null) interest = interest or Constants.EPOLLIN
            if (w.writer != null) interest = interest or Constants.EPOLLOUT
            epoll_event.events(ev, interest)
            epoll_data.fd(epoll_event.data(ev), fd)

            var rc = NativeH.epoll_ctl(epfd, Constants.EPOLL_CTL_ADD, fd, ev)
            if (rc == 0) return 0
            var err = Libc.errno()
            if (err == Constants.EEXIST) {
                rc = NativeH.epoll_ctl(epfd, Constants.EPOLL_CTL_MOD, fd, ev)
                if (rc == 0) return 0
                err = Libc.errno()
            }
            return err
        }
    }

    /** Remove [fd] from the epoll interest set. */
    fun remove(fd: Int) {
        waiters.remove(fd)
        NativeH.epoll_ctl(epfd, Constants.EPOLL_CTL_DEL, fd, MemorySegment.NULL)
    }

    /** Signal the driver loop to exit. Does not close the epoll fd. */
    fun shutdown() {
        isClosed = true
        // Wake up epoll_wait immediately via the pipe.
        Arena.ofConfined().use { arena ->
            val buf = arena.allocate(1)
            buf.set(ValueLayout.JAVA_BYTE, 0, 1.toByte())
            NativeH.write(wakeWriteFd, buf, 1)
        }
        for (w in waiters.values) {
            w.reader?.let { LockSupport.unpark(it) }
            w.writer?.let { LockSupport.unpark(it) }
        }
        waiters.clear()
    }

    override fun close() {
        shutdown()
        PosixIO.close(wakeReadFd)
        PosixIO.close(wakeWriteFd)
        PosixIO.close(epfd)
    }

    companion object {
        private const val MAX_EVENTS = 16
        private const val WAKEUP_FD = -2

        /** Create a new IoLoop backed by an epoll instance. */
        fun create(): IoLoop {
            val fd = NativeH.epoll_create1(Constants.EPOLL_CLOEXEC)
            if (fd < 0) {
                throw IllegalStateException("epoll_create1 failed (errno=${Libc.errno()})")
            }

            val pipeFds = createPipe()
            setNonBlocking(pipeFds[0])
            setNonBlocking(pipeFds[1])

            Arena.ofConfined().use { arena ->
                val ev = epoll_event.allocate(arena)
                epoll_event.events(ev, Constants.EPOLLIN)
                epoll_data.fd(epoll_event.data(ev), WAKEUP_FD)
                if (NativeH.epoll_ctl(fd, Constants.EPOLL_CTL_ADD, pipeFds[0], ev) != 0) {
                    PosixIO.close(pipeFds[0])
                    PosixIO.close(pipeFds[1])
                    PosixIO.close(fd)
                    throw IllegalStateException(
                        "epoll_ctl for wakeup pipe failed (errno=${Libc.errno()})"
                    )
                }
            }

            return IoLoop(fd, pipeFds[0], pipeFds[1])
        }

        private fun createPipe(): IntArray {
            Arena.ofConfined().use { arena ->
                val fds = arena.allocate(ValueLayout.JAVA_INT, 2)
                val rc = NativeH_3.pipe(fds)
                if (rc != 0) {
                    throw IllegalStateException("pipe() failed (errno=${Libc.errno()})")
                }
                return intArrayOf(
                    fds.getAtIndex(ValueLayout.JAVA_INT, 0),
                    fds.getAtIndex(ValueLayout.JAVA_INT, 1),
                )
            }
        }

        // -- Utility: set/clear O_NONBLOCK ------------------------------------

        fun setNonBlocking(fd: Int) {
            val flags = PosixIO.fcntl(fd, Constants.F_GETFL, 0)
            if (flags >= 0) {
                PosixIO.fcntl(fd, Constants.F_SETFL, flags or Constants.O_NONBLOCK)
            }
        }

        fun restoreBlocking(fd: Int) {
            val flags = PosixIO.fcntl(fd, Constants.F_GETFL, 0)
            if (flags >= 0) {
                PosixIO.fcntl(fd, Constants.F_SETFL, flags and Constants.O_NONBLOCK.inv())
            }
        }
    }
}
