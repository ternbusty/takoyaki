package com.ternbusty.takoyaki.exeseal

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.syscall.gen.NativeH
import java.lang.foreign.Arena
import java.nio.file.Files
import java.nio.file.Path

/**
 * CVE-2019-5736 mitigation: create a sealed clone of the runtime binary so that
 * container processes cannot overwrite the host binary through /proc/self/exe.
 *
 * Two strategies are tried in order:
 *
 *   1. overlayfs with lowerdir-only (zero-copy, no performance overhead)
 *   2. memfd_create + sendfile + F_SEAL_WRITE (~60% startup overhead)
 *
 * The returned fd is used as the exec target via /proc/self/fd/N. The child
 * process (and all its re-exec descendants) will see the sealed binary as
 * /proc/self/exe, making it impossible for a malicious container process to
 * overwrite the host runc/takoyaki binary.
 */
object ExeSeal {

    // Syscall numbers from jextract (arch-dependent, resolved at build time).
    private val NR_openat: Long       = NativeH.SYS_openat().toLong()
    private val NR_sendfile: Long     = NativeH.SYS_sendfile().toLong()
    private val NR_memfd_create: Long = NativeH.SYS_memfd_create().toLong()
    private val NR_fsopen: Long       = NativeH.SYS_fsopen().toLong()
    private val NR_fsconfig: Long     = NativeH.SYS_fsconfig().toLong()
    private val NR_fsmount: Long      = NativeH.SYS_fsmount().toLong()

    // fsconfig(2) commands (linux/mount.h)
    private const val FSCONFIG_SET_STRING = 1
    private const val FSCONFIG_CMD_CREATE = 6

    // fsopen/fsmount flags (linux/mount.h)
    private const val FSOPEN_CLOEXEC  = 0x00000001
    private const val FSMOUNT_CLOEXEC = 0x00000001

    // memfd_create(2) flags (linux/memfd.h)
    private const val MFD_CLOEXEC       = 0x0001
    private const val MFD_ALLOW_SEALING = 0x0002

    // fcntl(2) seal commands and flags (linux/fcntl.h)
    private const val F_ADD_SEALS   = 1033
    private const val F_SEAL_SEAL   = 0x0001
    private const val F_SEAL_SHRINK = 0x0002
    private const val F_SEAL_GROW   = 0x0004
    private const val F_SEAL_WRITE  = 0x0008
    private const val BASE_SEALS    = F_SEAL_SEAL or F_SEAL_SHRINK or F_SEAL_GROW or F_SEAL_WRITE

    // open(2) flags (asm-generic, same on aarch64 and x86_64)
    private const val O_RDONLY   = 0
    private const val O_CLOEXEC  = 0x80000
    private const val O_PATH     = 0x200000
    private const val O_NOFOLLOW = 0x20000
    private const val AT_FDCWD   = -100

    // Mount attribute flags for fsmount(2)
    private const val MS_RDONLY = 1
    private const val MS_NOSUID = 2
    private const val MS_NODEV  = 4

    /**
     * Create a sealed clone of /proc/self/exe. Returns the fd number on success
     * (caller uses "/proc/self/fd/" + fd as the exec path), or -1 on failure.
     *
     * The returned fd has O_CLOEXEC set. This is intentional: execve resolves
     * the /proc/self/fd/N path before closing CLOEXEC descriptors, so the child
     * can exec it. After exec, the kernel keeps the sealed binary alive as the
     * process executable (/proc/self/exe), even though the original fd is gone.
     *
     * @param tmpDir a directory to use as the dummy overlayfs lower layer
     *               (must exist; falls back to /tmp if the given path does not)
     */
    fun cloneSelfExe(tmpDir: String?): Int {
        // The dummy lowerdir must be an existing directory. The caller's
        // tmpDir (typically the runtime state root) may not exist yet at
        // this point. Fall back to /tmp which always exists.
        var dir = tmpDir
        if (dir == null || !Files.isDirectory(Path.of(dir))) {
            dir = "/tmp"
        }
        var fd = sealedOverlayfs(dir)
        if (fd >= 0) {
            Logger.debug("exeseal: using overlayfs for sealed /proc/self/exe")
            return fd
        }

        fd = sealedMemfd()
        if (fd >= 0) {
            Logger.debug("exeseal: using memfd for sealed /proc/self/exe")
            return fd
        }

        return -1
    }

    /**
     * Create a read-only overlayfs with the binary's directory as lowerdir.
     * Two lowerdirs and no upperdir puts overlayfs into "lower-only" mode where
     * all writes are rejected. This gives us a zero-copy sealed binary.
     */
    private fun sealedOverlayfs(tmpDir: String): Int {
        Arena.ofConfined().use { arena ->
            // fsopen("overlay", FSOPEN_CLOEXEC)
            val fsName = arena.allocateFrom("overlay")
            val ctxFd = Libc.syscall(NR_fsopen, fsName.address(),
                FSOPEN_CLOEXEC.toLong(), 0, 0, 0)
            if (ctxFd < 0) {
                Logger.debug("exeseal: fsopen(overlay) failed: ${Libc.strerror(Libc.errno())}")
                return -1
            }
            val ctx = ctxFd.toInt()

            try {
                val binPath = PosixIO.readlink(arena, "/proc/self/exe") ?: return -1

                val lastSlash = binPath.lastIndexOf('/')
                val binDir = if (lastSlash > 0) binPath.substring(0, lastSlash) else "/"
                val binName = binPath.substring(lastSlash + 1)

                // overlayfs uses ":" as a lowerdir separator, so escape literal
                // colons and backslashes in paths.
                val lowerDir = "${escapeOverlayPath(binDir)}:${escapeOverlayPath(tmpDir)}"

                // fsconfig(ctx, FSCONFIG_SET_STRING, "lowerdir", lowerDir, 0)
                val keyLower = arena.allocateFrom("lowerdir")
                val valLower = arena.allocateFrom(lowerDir)
                if (Libc.syscall(NR_fsconfig, ctx.toLong(), FSCONFIG_SET_STRING.toLong(),
                        keyLower.address(), valLower.address(), 0) < 0) {
                    Logger.debug("exeseal: fsconfig(lowerdir) failed: ${Libc.strerror(Libc.errno())}")
                    return -1
                }

                // Disable xino to suppress spurious dmesg warnings when the two
                // lowerdirs are on different filesystems. Ignore errors.
                val keyXino = arena.allocateFrom("xino")
                val valOff = arena.allocateFrom("off")
                Libc.syscall(NR_fsconfig, ctx.toLong(), FSCONFIG_SET_STRING.toLong(),
                    keyXino.address(), valOff.address(), 0)

                // fsconfig(ctx, FSCONFIG_CMD_CREATE)
                if (Libc.syscall(NR_fsconfig, ctx.toLong(), FSCONFIG_CMD_CREATE.toLong(),
                        0, 0, 0) < 0) {
                    Logger.debug("exeseal: fsconfig(CREATE) failed: ${Libc.strerror(Libc.errno())}")
                    return -1
                }

                // fsmount(ctx, FSMOUNT_CLOEXEC, MS_RDONLY|MS_NODEV|MS_NOSUID)
                val mountFdVal = Libc.syscall(NR_fsmount, ctx.toLong(),
                    FSMOUNT_CLOEXEC.toLong(), (MS_RDONLY or MS_NODEV or MS_NOSUID).toLong(), 0, 0)
                if (mountFdVal < 0) {
                    Logger.debug("exeseal: fsmount failed: ${Libc.strerror(Libc.errno())}")
                    return -1
                }
                val mountFd = mountFdVal.toInt()

                try {
                    // openat(mountFd, binName, O_PATH|O_NOFOLLOW|O_CLOEXEC, 0)
                    val name = arena.allocateFrom(binName)
                    val exeFd = Libc.syscall(NR_openat, mountFd.toLong(), name.address(),
                        (O_PATH or O_NOFOLLOW or O_CLOEXEC).toLong(), 0, 0)
                    if (exeFd < 0) {
                        Logger.debug("exeseal: openat(overlay/$binName) failed: " +
                            Libc.strerror(Libc.errno()))
                        return -1
                    }
                    return exeFd.toInt()
                } finally {
                    PosixIO.close(mountFd)
                }
            } finally {
                PosixIO.close(ctx)
            }
        }
    }

    /**
     * Copy the binary into a sealed memfd. The memfd is sealed with
     * F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL so that no process
     * (including one with the fd) can modify its contents.
     */
    private fun sealedMemfd(): Int {
        try {
            Arena.ofConfined().use { arena ->
                val name = arena.allocateFrom("takoyaki_cloned:/proc/self/exe")
                val memFdVal = Libc.syscall(NR_memfd_create, name.address(),
                    (MFD_ALLOW_SEALING or MFD_CLOEXEC).toLong(), 0, 0, 0)
                if (memFdVal < 0) {
                    Logger.debug("exeseal: memfd_create failed: ${Libc.strerror(Libc.errno())}")
                    return -1
                }
                val memFd = memFdVal.toInt()

                var success = false
                try {
                    // Open the current binary for reading.
                    val exePath = arena.allocateFrom("/proc/self/exe")
                    val srcFdVal = Libc.syscall(NR_openat, AT_FDCWD.toLong(), exePath.address(),
                        (O_RDONLY or O_CLOEXEC).toLong(), 0, 0)
                    if (srcFdVal < 0) {
                        Logger.debug("exeseal: open /proc/self/exe failed: " +
                            "${Libc.strerror(Libc.errno())}")
                        return -1
                    }
                    val srcFd = srcFdVal.toInt()

                    try {
                        val size = Files.size(Path.of("/proc/self/exe"))
                        var remaining = size
                        while (remaining > 0) {
                            // sendfile(memFd, srcFd, NULL, remaining)
                            val sent = Libc.syscall(NR_sendfile, memFd.toLong(), srcFd.toLong(),
                                0, remaining, 0)
                            if (sent <= 0) {
                                Logger.debug("exeseal: sendfile failed after " +
                                    "${size - remaining}/$size bytes: ${Libc.strerror(Libc.errno())}")
                                return -1
                            }
                            remaining -= sent
                        }
                    } finally {
                        PosixIO.close(srcFd)
                    }

                    // Seal the memfd so nobody can modify the binary contents.
                    if (PosixIO.fcntl(memFd, F_ADD_SEALS, BASE_SEALS) < 0) {
                        Logger.debug("exeseal: F_ADD_SEALS failed: ${Libc.strerror(Libc.errno())}")
                        return -1
                    }

                    success = true
                    return memFd
                } finally {
                    if (!success) PosixIO.close(memFd)
                }
            }
        } catch (e: Exception) {
            Logger.debug("exeseal: memfd sealing failed: ${e.message}")
            return -1
        }
    }

    private fun escapeOverlayPath(path: String): String =
        path.replace("\\", "\\\\").replace(":", "\\:")
}
