package com.ternbusty.takoyaki.ioloop;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;
import com.ternbusty.takoyaki.syscall.gen.NativeH_3;
import com.ternbusty.takoyaki.syscall.gen.epoll_data;
import com.ternbusty.takoyaki.syscall.gen.epoll_event;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.LockSupport;

/**
 * Epoll-backed I/O loop that suspends virtual threads instead of blocking
 * platform threads.
 *
 * <p>Each {@code awaitReadable}/{@code awaitWritable} call parks the (virtual)
 * calling thread.  The caller's platform thread drives the loop via
 * {@link #run()}, calling {@code epoll_wait} and unparking waiters as their
 * fds become ready — no extra thread is spawned.
 *
 * <p>Thread safety: {@link #awaitReadable}/{@link #awaitWritable} may be called
 * from any thread; the waiter map is a {@link ConcurrentHashMap} and
 * {@code epoll_ctl} is thread-safe in the kernel.
 */
public final class IoLoop implements AutoCloseable {

    private static final int MAX_EVENTS = 16;
    private static final int WAKEUP_FD = -2;

    /** Per-fd waiter slots. */
    private static final class FdWaiters {
        volatile Thread reader;
        volatile Thread writer;
    }

    private final int epfd;
    private final int wakeReadFd;
    private final int wakeWriteFd;
    private final Map<Integer, FdWaiters> waiters = new ConcurrentHashMap<>();
    private volatile boolean closed;

    private IoLoop(int epfd, int wakeReadFd, int wakeWriteFd) {
        this.epfd = epfd;
        this.wakeReadFd = wakeReadFd;
        this.wakeWriteFd = wakeWriteFd;
    }

    /** Create a new IoLoop backed by an epoll instance. */
    public static IoLoop create() {
        int fd = NativeH.epoll_create1(Constants.EPOLL_CLOEXEC);
        if (fd < 0) {
            throw new IllegalStateException(
                    "epoll_create1 failed (errno=" + Libc.errno() + ")");
        }

        int[] pipeFds = createPipe();
        setNonBlocking(pipeFds[0]);
        setNonBlocking(pipeFds[1]);

        try (var arena = Arena.ofConfined()) {
            MemorySegment ev = epoll_event.allocate(arena);
            epoll_event.events(ev, Constants.EPOLLIN);
            epoll_data.fd(epoll_event.data(ev), WAKEUP_FD);
            if (NativeH.epoll_ctl(fd, Constants.EPOLL_CTL_ADD, pipeFds[0], ev) != 0) {
                PosixIO.close(pipeFds[0]);
                PosixIO.close(pipeFds[1]);
                PosixIO.close(fd);
                throw new IllegalStateException(
                        "epoll_ctl for wakeup pipe failed (errno=" + Libc.errno() + ")");
            }
        }

        return new IoLoop(fd, pipeFds[0], pipeFds[1]);
    }

    private static int[] createPipe() {
        try (var arena = Arena.ofConfined()) {
            MemorySegment fds = arena.allocate(ValueLayout.JAVA_INT, 2);
            int rc = NativeH_3.pipe(fds);
            if (rc != 0) {
                throw new IllegalStateException(
                        "pipe() failed (errno=" + Libc.errno() + ")");
            }
            return new int[]{
                    fds.getAtIndex(ValueLayout.JAVA_INT, 0),
                    fds.getAtIndex(ValueLayout.JAVA_INT, 1)
            };
        }
    }

    /**
     * Run the driver loop on the calling thread.  Blocks until
     * {@link #shutdown()} is called, then returns.
     */
    public void run() {
        try (var arena = Arena.ofConfined()) {
            long eventSize = epoll_event.layout().byteSize();
            MemorySegment events = arena.allocate(eventSize * MAX_EVENTS);
            while (!closed) {
                int n = NativeH.epoll_wait(epfd, events, MAX_EVENTS, -1);
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

                    if (fd == WAKEUP_FD) continue;

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

    /** Park the calling virtual thread until {@code fd} is readable. */
    public void awaitReadable(int fd) {
        awaitEvent(fd, false);
    }

    /** Park the calling virtual thread until {@code fd} is writable. */
    public void awaitWritable(int fd) {
        awaitEvent(fd, true);
    }

    private void awaitEvent(int fd, boolean wantWrite) {
        if (closed) return;
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
                return;
            }
            throw new IllegalStateException(
                    "epoll_ctl failed for fd=" + fd + " (errno=" + rc + ")");
        }
        // Re-check after registration: shutdown() may have iterated
        // waiters between our first check and here, missing this entry.
        // If shutdown() runs after this check but before park(), its
        // unpark() sets a permit that park() consumes immediately.
        if (closed) {
            if (wantWrite) w.writer = null; else w.reader = null;
            return;
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

    /** True after {@link #shutdown()} has been called. */
    public boolean isClosed() { return closed; }

    /** Signal the driver loop to exit. Does not close the epoll fd. */
    public void shutdown() {
        closed = true;
        // Wake up epoll_wait immediately via the pipe.
        try (var arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocate(1);
            buf.set(ValueLayout.JAVA_BYTE, 0, (byte) 1);
            NativeH.write(wakeWriteFd, buf, 1);
        }
        for (var w : waiters.values()) {
            Thread t = w.reader;
            if (t != null) LockSupport.unpark(t);
            t = w.writer;
            if (t != null) LockSupport.unpark(t);
        }
        waiters.clear();
    }

    @Override
    public void close() {
        shutdown();
        PosixIO.close(wakeReadFd);
        PosixIO.close(wakeWriteFd);
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
