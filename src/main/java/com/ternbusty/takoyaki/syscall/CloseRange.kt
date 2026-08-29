package com.ternbusty.takoyaki.syscall

import com.ternbusty.takoyaki.logger.Logger
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

object CloseRange {

    fun closeAllAbove(preserveFds: Int) {
        val minFd = 3 + preserveFds
        val rc = Libc.syscall(
            Constants.NR_close_range,
            minFd.toLong(), Int.MAX_VALUE.toLong(),
            Constants.CLOSE_RANGE_CLOEXEC.toLong(), 0L, 0L
        )
        if (rc == -1L) {
            val e = Libc.errno()
            if (e == Constants.ENOSYS || e == Constants.EINVAL) {
                Logger.debug("close_range unsupported (errno=$e), falling back")
            } else {
                Logger.warn("close_range failed: ${Libc.strerror(e)}")
            }
            fallbackCloexec(minFd)
        } else {
            Logger.debug("close_range applied for fds >= $minFd")
        }
    }

    /**
     * Actually close all fds >= 3 except the specified one. Unlike
     * [closeAllAbove] which only sets CLOEXEC, this really closes
     * fds so they are not visible in /proc/self/fd during the "created" wait.
     */
    fun closeAllExcept(keepFd: Int) {
        val fds = mutableListOf<Int>()
        try {
            Files.newDirectoryStream(Path.of("/proc/self/fd")).use { ds ->
                for (p in ds) {
                    try {
                        val fd = p.fileName.toString().toInt()
                        if (fd >= 3 && fd != keepFd) fds.add(fd)
                    } catch (_: NumberFormatException) {
                    }
                }
            }
        } catch (e: IOException) {
            Logger.warn("closeAllExcept: failed to enumerate fds: ${e.message}")
            return
        }
        for (fd in fds) {
            PosixIO.close(fd)
        }
        Logger.debug("closed ${fds.size} fds (kept fd $keepFd)")
    }

    private fun fallbackCloexec(minFd: Int) {
        val fds = mutableListOf<Int>()
        try {
            Files.newDirectoryStream(Path.of("/proc/self/fd")).use { ds ->
                for (p in ds) {
                    try {
                        val fd = p.fileName.toString().toInt()
                        if (fd >= minFd) fds.add(fd)
                    } catch (_: NumberFormatException) {
                    }
                }
            }
        } catch (e: IOException) {
            Logger.warn("failed to enumerate /proc/self/fd: ${e.message}")
            return
        }
        for (fd in fds) {
            val flags = PosixIO.fcntl(fd, Constants.F_GETFD, 0)
            if (flags == -1) continue
            PosixIO.fcntl(fd, Constants.F_SETFD, flags or Constants.FD_CLOEXEC)
        }
        Logger.debug("fallback CLOEXEC set on ${fds.size} fds")
    }
}
