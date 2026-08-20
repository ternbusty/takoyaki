package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.logger.Logger;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class CloseRange {
    private CloseRange() {}

    public static void closeAllAbove(int preserveFds) {
        int minFd = 3 + preserveFds;
        long rc = Libc.syscall(Constants.NR_close_range,
                (long) minFd, (long) Integer.MAX_VALUE,
                (long) Constants.CLOSE_RANGE_CLOEXEC, 0L, 0L);
        if (rc == -1) {
            int e = Libc.errno();
            if (e == Constants.ENOSYS || e == Constants.EINVAL) {
                Logger.debug("close_range unsupported (errno=" + e + "), falling back");
            } else {
                Logger.warn("close_range failed: " + Libc.strerror(e));
            }
            fallbackCloexec(minFd);
        } else {
            Logger.debug("close_range applied for fds >= " + minFd);
        }
    }

    /**
     * Actually close all fds >= 3 except the specified one. Unlike
     * {@link #closeAllAbove(int)} which only sets CLOEXEC, this really closes
     * fds so they are not visible in /proc/self/fd during the "created" wait.
     */
    public static void closeAllExcept(int keepFd) {
        List<Integer> fds = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(Path.of("/proc/self/fd"))) {
            for (Path p : ds) {
                try {
                    int fd = Integer.parseInt(p.getFileName().toString());
                    if (fd >= 3 && fd != keepFd) fds.add(fd);
                } catch (NumberFormatException ignored) {}
            }
        } catch (IOException e) {
            Logger.warn("closeAllExcept: failed to enumerate fds: " + e.getMessage());
            return;
        }
        for (int fd : fds) {
            PosixIO.close(fd);
        }
        Logger.debug("closed " + fds.size() + " fds (kept fd " + keepFd + ")");
    }

    private static void fallbackCloexec(int minFd) {
        List<Integer> fds = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(Path.of("/proc/self/fd"))) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                try {
                    int fd = Integer.parseInt(name);
                    if (fd >= minFd) fds.add(fd);
                } catch (NumberFormatException ignored) {}
            }
        } catch (IOException e) {
            Logger.warn("failed to enumerate /proc/self/fd: " + e.getMessage());
            return;
        }
        for (int fd : fds) {
            int flags = PosixIO.fcntl(fd, Constants.F_GETFD, 0);
            if (flags == -1) continue;
            PosixIO.fcntl(fd, Constants.F_SETFD, flags | Constants.FD_CLOEXEC);
        }
        Logger.debug("fallback CLOEXEC set on " + fds.size() + " fds");
    }
}
