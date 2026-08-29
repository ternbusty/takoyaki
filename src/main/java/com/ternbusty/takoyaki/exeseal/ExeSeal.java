package com.ternbusty.takoyaki.exeseal;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;

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
public final class ExeSeal {
    private ExeSeal() {}

    // Syscall numbers from jextract (arch-dependent, resolved at build time).
    private static final long NR_openat       = NativeH.SYS_openat();
    private static final long NR_sendfile     = NativeH.SYS_sendfile();
    private static final long NR_memfd_create = NativeH.SYS_memfd_create();
    private static final long NR_fsopen       = NativeH.SYS_fsopen();
    private static final long NR_fsconfig     = NativeH.SYS_fsconfig();
    private static final long NR_fsmount      = NativeH.SYS_fsmount();

    // fsconfig(2) commands (linux/mount.h)
    private static final int FSCONFIG_SET_STRING = 1;
    private static final int FSCONFIG_CMD_CREATE = 6;

    // fsopen/fsmount flags (linux/mount.h)
    private static final int FSOPEN_CLOEXEC  = 0x00000001;
    private static final int FSMOUNT_CLOEXEC = 0x00000001;

    // memfd_create(2) flags (linux/memfd.h)
    private static final int MFD_CLOEXEC       = 0x0001;
    private static final int MFD_ALLOW_SEALING = 0x0002;

    // fcntl(2) seal commands and flags (linux/fcntl.h)
    private static final int F_ADD_SEALS   = 1033;
    private static final int F_SEAL_SEAL   = 0x0001;
    private static final int F_SEAL_SHRINK = 0x0002;
    private static final int F_SEAL_GROW   = 0x0004;
    private static final int F_SEAL_WRITE  = 0x0008;
    private static final int BASE_SEALS    = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

    // open(2) flags (asm-generic, same on aarch64 and x86_64)
    private static final int O_RDONLY   = 0;
    private static final int O_CLOEXEC  = 0x80000;
    private static final int O_PATH     = 0x200000;
    private static final int O_NOFOLLOW = 0x20000;
    private static final int AT_FDCWD   = -100;

    // Mount attribute flags for fsmount(2)
    private static final int MS_RDONLY = 1;
    private static final int MS_NOSUID = 2;
    private static final int MS_NODEV  = 4;

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
    public static int cloneSelfExe(String tmpDir) {
        // The dummy lowerdir must be an existing directory. The caller's
        // tmpDir (typically the runtime state root) may not exist yet at
        // this point. Fall back to /tmp which always exists.
        if (tmpDir == null || !java.nio.file.Files.isDirectory(java.nio.file.Path.of(tmpDir))) {
            tmpDir = "/tmp";
        }
        int fd = sealedOverlayfs(tmpDir);
        if (fd >= 0) {
            Logger.debug("exeseal: using overlayfs for sealed /proc/self/exe");
            return fd;
        }

        fd = sealedMemfd();
        if (fd >= 0) {
            Logger.debug("exeseal: using memfd for sealed /proc/self/exe");
            return fd;
        }

        return -1;
    }

    /**
     * Create a read-only overlayfs with the binary's directory as lowerdir.
     * Two lowerdirs and no upperdir puts overlayfs into "lower-only" mode where
     * all writes are rejected. This gives us a zero-copy sealed binary.
     */
    private static int sealedOverlayfs(String tmpDir) {
        try (Arena arena = Arena.ofConfined()) {
            // fsopen("overlay", FSOPEN_CLOEXEC)
            MemorySegment fsName = arena.allocateFrom("overlay");
            long ctxFd = Libc.syscall(NR_fsopen, fsName.address(), FSOPEN_CLOEXEC, 0, 0, 0);
            if (ctxFd < 0) {
                Logger.debug("exeseal: fsopen(overlay) failed: " + Libc.strerror(Libc.errno()));
                return -1;
            }
            int ctx = (int) ctxFd;

            try {
                String binPath = PosixIO.readlink(arena, "/proc/self/exe");
                if (binPath == null) return -1;

                int lastSlash = binPath.lastIndexOf('/');
                String binDir = lastSlash > 0 ? binPath.substring(0, lastSlash) : "/";
                String binName = binPath.substring(lastSlash + 1);

                // overlayfs uses ":" as a lowerdir separator, so escape literal
                // colons and backslashes in paths.
                String lowerDir = escapeOverlayPath(binDir) + ":" + escapeOverlayPath(tmpDir);

                // fsconfig(ctx, FSCONFIG_SET_STRING, "lowerdir", lowerDir, 0)
                MemorySegment keyLower = arena.allocateFrom("lowerdir");
                MemorySegment valLower = arena.allocateFrom(lowerDir);
                if (Libc.syscall(NR_fsconfig, ctx, FSCONFIG_SET_STRING,
                        keyLower.address(), valLower.address(), 0) < 0) {
                    Logger.debug("exeseal: fsconfig(lowerdir) failed: " + Libc.strerror(Libc.errno()));
                    return -1;
                }

                // Disable xino to suppress spurious dmesg warnings when the two
                // lowerdirs are on different filesystems. Ignore errors.
                MemorySegment keyXino = arena.allocateFrom("xino");
                MemorySegment valOff = arena.allocateFrom("off");
                Libc.syscall(NR_fsconfig, ctx, FSCONFIG_SET_STRING,
                        keyXino.address(), valOff.address(), 0);

                // fsconfig(ctx, FSCONFIG_CMD_CREATE)
                if (Libc.syscall(NR_fsconfig, ctx, FSCONFIG_CMD_CREATE, 0, 0, 0) < 0) {
                    Logger.debug("exeseal: fsconfig(CREATE) failed: " + Libc.strerror(Libc.errno()));
                    return -1;
                }

                // fsmount(ctx, FSMOUNT_CLOEXEC, MS_RDONLY|MS_NODEV|MS_NOSUID)
                long mountFdVal = Libc.syscall(NR_fsmount, ctx, FSMOUNT_CLOEXEC,
                        MS_RDONLY | MS_NODEV | MS_NOSUID, 0, 0);
                if (mountFdVal < 0) {
                    Logger.debug("exeseal: fsmount failed: " + Libc.strerror(Libc.errno()));
                    return -1;
                }
                int mountFd = (int) mountFdVal;

                try {
                    // openat(mountFd, binName, O_PATH|O_NOFOLLOW|O_CLOEXEC, 0)
                    MemorySegment name = arena.allocateFrom(binName);
                    long exeFd = Libc.syscall(NR_openat, mountFd, name.address(),
                            O_PATH | O_NOFOLLOW | O_CLOEXEC, 0, 0);
                    if (exeFd < 0) {
                        Logger.debug("exeseal: openat(overlay/" + binName + ") failed: "
                                + Libc.strerror(Libc.errno()));
                        return -1;
                    }
                    return (int) exeFd;
                } finally {
                    PosixIO.close(mountFd);
                }
            } finally {
                PosixIO.close(ctx);
            }
        }
    }

    /**
     * Copy the binary into a sealed memfd. The memfd is sealed with
     * F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL so that no process
     * (including one with the fd) can modify its contents.
     */
    private static int sealedMemfd() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment name = arena.allocateFrom("takoyaki_cloned:/proc/self/exe");
            long memFdVal = Libc.syscall(NR_memfd_create, name.address(),
                    MFD_ALLOW_SEALING | MFD_CLOEXEC, 0, 0, 0);
            if (memFdVal < 0) {
                Logger.debug("exeseal: memfd_create failed: " + Libc.strerror(Libc.errno()));
                return -1;
            }
            int memFd = (int) memFdVal;

            boolean success = false;
            try {
                // Open the current binary for reading.
                MemorySegment exePath = arena.allocateFrom("/proc/self/exe");
                long srcFdVal = Libc.syscall(NR_openat, AT_FDCWD, exePath.address(),
                        O_RDONLY | O_CLOEXEC, 0, 0);
                if (srcFdVal < 0) {
                    Logger.debug("exeseal: open /proc/self/exe failed: " + Libc.strerror(Libc.errno()));
                    return -1;
                }
                int srcFd = (int) srcFdVal;

                try {
                    long size = Files.size(Path.of("/proc/self/exe"));
                    long remaining = size;
                    while (remaining > 0) {
                        // sendfile(memFd, srcFd, NULL, remaining)
                        long sent = Libc.syscall(NR_sendfile, memFd, srcFd,
                                0, remaining, 0);
                        if (sent <= 0) {
                            Logger.debug("exeseal: sendfile failed after " + (size - remaining)
                                    + "/" + size + " bytes: " + Libc.strerror(Libc.errno()));
                            return -1;
                        }
                        remaining -= sent;
                    }
                } finally {
                    PosixIO.close(srcFd);
                }

                // Seal the memfd so nobody can modify the binary contents.
                if (PosixIO.fcntl(memFd, F_ADD_SEALS, BASE_SEALS) < 0) {
                    Logger.debug("exeseal: F_ADD_SEALS failed: " + Libc.strerror(Libc.errno()));
                    return -1;
                }

                success = true;
                return memFd;
            } finally {
                if (!success) PosixIO.close(memFd);
            }
        } catch (Exception e) {
            Logger.debug("exeseal: memfd sealing failed: " + e.getMessage());
            return -1;
        }
    }

    private static String escapeOverlayPath(String path) {
        return path.replace("\\", "\\\\").replace(":", "\\:");
    }
}
