package com.ternbusty.takoyaki.ioloop;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;
import com.ternbusty.takoyaki.syscall.gen.epoll_data;
import com.ternbusty.takoyaki.syscall.gen.epoll_event;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.LockSupport;

/**
 * Epoll-backed I/O loop that suspends virtual threads instead of blocking
 * platform threads — a miniature equivalent of Go's netpoller and
 * kontainer-runtime's coroutine-based {@code IoLoop}.
 *
 * <p>Each {@code awaitReadable}/{@code awaitWritable} call parks the (virtual)
 * calling thread.  A single driver thread loops over {@code epoll_wait} and
 * unparks waiters as their fds become ready.
 *
 * <p>Thread safety: {@link #awaitReadable}/{@link #awaitWritable} may be called
 * from any thread; the waiter map is a {@link ConcurrentHashMap} and
 * {@code epoll_ctl} is thread-safe in the kernel.
 */
public final class IoLoop implements AutoCloseable {

    private static final int MAX_EVENTS = 16;
    private static final int DRIVER_TIMEOUT_MS = 50;

    /** Per-fd waiter slots. */
    private static final class FdWaiters {
        volatile Thread reader;
        volatile Thread writer;
    }

    private final int epfd;
    private final Map<Integer, FdWaiters> waiters = new ConcurrentHashMap<>();
    private volatile boolean closed;
    private Thread driverThread;

    private IoLoop(int epfd) {
        this.epfd = epfd;
    }

    /** Create a new IoLoop backed by an epoll instance. */
    public static IoLoop create() {
        int fd = NativeH.epoll_create1(Constants.EPOLL_CLOEXEC);
        if (fd < 0) {
            throw new IllegalStateException(
                    "epoll_create1 failed (errno=" + Libc.errno() + ")");
        }
        return new IoLoop(fd);
    }

    /**
     * Start the driver thread that runs {@code epoll_wait} in a loop and
     * unparks virtual threads whose fds are ready.
     */
    public void startDriver() {
        driverThread = Thread.ofPlatform()
                .name("ioloop-driver")
                .daemon(true)
                .start(this::driverLoop);
    }

    /** Park the calling virtual thread until {@code fd} is readable. */
    public void awaitReadable(int fd) {
        awaitEvent(fd, false);
    }

    /** Park the calling virtual thread until {@code fd} is writable. */
    public void awaitWritable(int fd) {
        awaitEvent(fd, true);
    }

    private void awaitEvent(int fd, boolean wantWrite) {
        var w = waiters.computeIfAbsent(fd, k -> new FdWaiters());
        if (wantWrite) {
            w.writer = Thread.currentThread();
        } else {
            w.reader = Thread.currentThread();
        }
        int rc = arm(fd, w);
        if (rc != 0) {
            if (wantWrite) w.writer = null; else w.reader = null;
            if (w.reader == null && w.writer == null) waiters.remove(fd);
            if (rc == Constants.EPERM) {
                // fd doesn't support epoll (regular file). Treat as ready.
                return;
            }
            throw new IllegalStateException(
                    "epoll_ctl failed for fd=" + fd + " (errno=" + rc + ")");
        }
        LockSupport.park(this);
    }

    /**
     * (Re-)register {@code fd} with EPOLLONESHOT and the interest set implied
     * by its current waiters.
     *
     * @return 0 on success, errno on failure
     */
    private int arm(int fd, FdWaiters w) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment ev = epoll_event.allocate(arena);
            int interest = Constants.EPOLLONESHOT;
            if (w.reader != null) interest |= Constants.EPOLLIN;
            if (w.writer != null) interest |= Constants.EPOLLOUT;
            epoll_event.events(ev, interest);
            epoll_data.fd(epoll_event.data(ev), fd);

            int rc = NativeH.epoll_ctl(epfd, Constants.EPOLL_CTL_ADD, fd, ev);
            if (rc == 0) return 0;
            int err = Libc.errno();
            if (err == Constants.EEXIST) {
                rc = NativeH.epoll_ctl(epfd, Constants.EPOLL_CTL_MOD, fd, ev);
                if (rc == 0) return 0;
                err = Libc.errno();
            }
            return err;
        }
    }

    /** Remove {@code fd} from the epoll interest set. */
    public void remove(int fd) {
        waiters.remove(fd);
        NativeH.epoll_ctl(epfd, Constants.EPOLL_CTL_DEL, fd, MemorySegment.NULL);
    }

    /**
     * The driver loop — runs on a dedicated platform thread, calling
     * {@code epoll_wait} and unparking virtual threads.
     */
    private void driverLoop() {
        try (var arena = Arena.ofConfined()) {
            long eventSize = epoll_event.layout().byteSize();
            MemorySegment events = arena.allocate(eventSize * MAX_EVENTS);
            while (!closed) {
                int n = NativeH.epoll_wait(epfd, events, MAX_EVENTS,
                        DRIVER_TIMEOUT_MS);
                if (n < 0) {
                    if (Libc.errno() == Constants.EINTR) continue;
                    if (closed) break;
                    Logger.debug("ioloop: epoll_wait error errno="
                            + Libc.errno());
                    continue;
                }
                for (int i = 0; i < n; i++) {
                    MemorySegment ev = events.asSlice(i * eventSize, eventSize);
                    int bits = epoll_event.events(ev);
                    int fd   = epoll_data.fd(epoll_event.data(ev));
                    var w = waiters.get(fd);
                    if (w == null) continue;

                    boolean hupOrErr = (bits
                            & (Constants.EPOLLHUP | Constants.EPOLLERR)) != 0;

                    if ((bits & Constants.EPOLLIN) != 0 || hupOrErr) {
                        Thread t = w.reader;
                        if (t != null) {
                            w.reader = null;
                            LockSupport.unpark(t);
                        }
                    }
                    if ((bits & Constants.EPOLLOUT) != 0 || hupOrErr) {
                        Thread t = w.writer;
                        if (t != null) {
                            w.writer = null;
                            LockSupport.unpark(t);
                        }
                    }

                    if (w.reader != null || w.writer != null) {
                        arm(fd, w);
                    } else {
                        waiters.remove(fd);
                    }
                }
            }
        }
    }

    @Override
    public void close() {
        closed = true;
        for (var w : waiters.values()) {
            Thread t = w.reader;
            if (t != null) LockSupport.unpark(t);
            t = w.writer;
            if (t != null) LockSupport.unpark(t);
        }
        waiters.clear();
        if (driverThread != null) {
            try { driverThread.join(500); } catch (InterruptedException ignored) {}
        }
        PosixIO.close(epfd);
    }

    // ── Utility: set/clear O_NONBLOCK ────────────────────────────────────

    public static void setNonBlocking(int fd) {
        int flags = PosixIO.fcntl(fd, Constants.F_GETFL, 0);
        if (flags >= 0) {
            PosixIO.fcntl(fd, Constants.F_SETFL, flags | Constants.O_NONBLOCK);
        }
    }

    public static void restoreBlocking(int fd) {
        int flags = PosixIO.fcntl(fd, Constants.F_GETFL, 0);
        if (flags >= 0) {
            PosixIO.fcntl(fd, Constants.F_SETFL, flags & ~Constants.O_NONBLOCK);
        }
    }
}
