package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.ffi.structs.open_how;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Opens and creates paths inside a container rootfs through a handle on the
 * rootfs, for the mounts the spec asks for.
 *
 * <p>A path string is looked up again by every syscall that takes it, and the
 * kernel follows symlinks in it from the host's root. If another process can
 * write into the rootfs while the mounts are made (a container that shares a
 * volume with it), it can swap a directory on the path for a symlink after the
 * runtime checked the path and before mount(2) uses it, and the mount lands
 * outside the rootfs (CVE-2021-30465 in runc). So, as runc does, mount points
 * are opened here with openat2(RESOLVE_IN_ROOT), which makes the kernel resolve
 * symlinks and ".." as if the rootfs were "/", and the mount is made on
 * {@link #fdPath} of the opened handle rather than on the path: whatever is
 * swapped in afterwards, the mount goes to the object that was opened.
 *
 * <p>Without openat2 (kernel before 5.6) the path is opened as a string and the
 * handle is then checked to be inside the rootfs, so a swap can make the mount
 * fail but not land outside.
 *
 * <p>Methods returning an fd return -1 on failure, with the cause in
 * {@link #errno}.
 */
final class InRoot implements AutoCloseable {

    private static final long RESOLVE = Constants.RESOLVE_IN_ROOT | Constants.RESOLVE_NO_MAGICLINKS;
    private static final int DIR_FLAGS = Constants.O_PATH | Constants.O_DIRECTORY | Constants.O_CLOEXEC;
    private static final int PATH_FLAGS = Constants.O_PATH | Constants.O_CLOEXEC;
    private static final int CREATE_FLAGS = Constants.O_CREAT | Constants.O_EXCL | Constants.O_NOFOLLOW
            | Constants.O_RDONLY | Constants.O_CLOEXEC;

    private final String rootfs;
    private final int rootFd;
    private final boolean openat2;
    private int errno;

    private InRoot(String rootfs, int rootFd, boolean openat2) {
        this.rootfs = rootfs;
        this.rootFd = rootFd;
        this.openat2 = openat2;
    }

    /** Open a handle on {@code rootfsPath}; null if it cannot be opened. */
    static InRoot of(String rootfsPath) {
        return of(rootfsPath, true);
    }

    /** As {@link #of(String)}; {@code tryOpenat2 = false} takes the fallback path (tests). */
    static InRoot of(String rootfsPath, boolean tryOpenat2) {
        int fd;
        try (Arena arena = Arena.ofConfined()) {
            fd = PosixIO.open(arena, rootfsPath, DIR_FLAGS, 0);
        }
        if (fd < 0) return null;
        String real = realPath(fd);
        if (real == null) {
            PosixIO.close(fd);
            return null;
        }
        boolean useOpenat2 = false;
        if (tryOpenat2) {
            int probe = openat2(fd, ".", DIR_FLAGS, 0, RESOLVE);
            if (probe >= 0) {
                PosixIO.close(probe);
                useOpenat2 = true;
            } else {
                Logger.debug("openat2 unavailable (" + Libc.strerror(Libc.errno())
                        + "), checking mount points after opening them");
            }
        }
        return new InRoot(real, fd, useOpenat2);
    }

    /** The rootfs path with symlinks resolved, as {@link #realPath} reports paths under it. */
    String rootfs() { return rootfs; }

    /** errno of the last failed call. */
    int errno() { return errno; }

    /** /proc/thread-self/fd/N: names the object {@code fd} refers to for path-taking syscalls. */
    static String fdPath(int fd) {
        return "/proc/thread-self/fd/" + fd;
    }

    /** The path {@code fd} refers to, as the kernel reports it, or null. */
    static String realPath(int fd) {
        try (Arena arena = Arena.ofConfined()) {
            return PosixIO.readlink(arena, fdPath(fd));
        }
    }

    /**
     * Open {@code path} with O_PATH. The path is taken relative to the rootfs:
     * a leading "/", or the rootfs path itself as a prefix, is dropped.
     */
    int open(String path) {
        return open(relative(path), PATH_FLAGS);
    }

    /** Create the directory {@code path} and its missing parents, and open it with O_PATH. */
    int mkdirAll(String path, int mode) {
        String rel = relative(path);
        int fd = open(rel, DIR_FLAGS);
        if (fd >= 0 || errno != Constants.ENOENT) return fd;
        if (!openat2) {
            try {
                Files.createDirectories(Path.of(rootfs, rel));
            } catch (IOException e) {
                Logger.debug("mkdir " + rel + " in rootfs: " + e.getMessage());
            }
            return open(rel, DIR_FLAGS);
        }
        // Make each missing component in the directory its parent resolves to
        // inside the rootfs, so a symlink swapped in on the way still resolves
        // inside the rootfs.
        String prefix = "";
        for (String comp : rel.split("/")) {
            if (comp.isEmpty() || comp.equals(".")) continue;
            String next = prefix.isEmpty() ? comp : prefix + "/" + comp;
            int dir = open(next, DIR_FLAGS);
            if (dir < 0 && errno == Constants.ENOENT) {
                int parent = open(prefix, DIR_FLAGS);
                if (parent < 0) return -1;
                int rc;
                int err;
                try (Arena arena = Arena.ofConfined()) {
                    rc = NativeH.mkdirat(parent, arena.allocateFrom(comp), mode);
                    err = Libc.errno();
                }
                PosixIO.close(parent);
                if (rc != 0 && err != Constants.EEXIST) return fail(err);
                dir = open(next, DIR_FLAGS);
            }
            if (dir < 0) return -1;
            PosixIO.close(dir);
            prefix = next;
        }
        return open(rel, DIR_FLAGS);
    }

    /**
     * Create the regular file {@code path} (and missing parent directories) if
     * it does not exist, and open it with O_PATH.
     */
    int createFile(String path, int mode) {
        String rel = relative(path);
        int fd = open(rel, PATH_FLAGS);
        if (fd >= 0 || errno != Constants.ENOENT) return fd;
        int slash = rel.lastIndexOf('/');
        int parent = mkdirAll(slash < 0 ? "" : rel.substring(0, slash), 0755);
        if (parent < 0) return -1;
        int created;
        int err;
        if (openat2) {
            created = openat2(parent, rel.substring(slash + 1), CREATE_FLAGS, mode,
                    Constants.RESOLVE_NO_SYMLINKS);
            err = Libc.errno();
        } else {
            try (Arena arena = Arena.ofConfined()) {
                created = PosixIO.open(arena, rootfs + "/" + rel, CREATE_FLAGS, mode);
                err = Libc.errno();
            }
        }
        PosixIO.close(parent);
        if (created >= 0) {
            PosixIO.close(created);
        } else if (err != Constants.EEXIST) {
            return fail(err);
        }
        return open(rel, PATH_FLAGS);
    }

    /**
     * After a mount on {@code fd}, open the new mount's root at the same path
     * (fd still refers to the directory that was mounted over). Fails if the
     * path no longer leads there, so later vfsmount flags do not go to another
     * mount; runc's reopenAfterMount makes the same check.
     */
    int reopenAfterMount(int fd) {
        String full = realPath(fd);
        if (full == null || !isInRoot(full)) return fail(Constants.EINVAL);
        int reopened = open(relative(full), PATH_FLAGS);
        if (reopened < 0) return -1;
        if (!full.equals(realPath(reopened))) {
            Logger.warn("mount point " + full + " was moved while re-opening it");
            PosixIO.close(reopened);
            return fail(Constants.EINVAL);
        }
        return reopened;
    }

    @Override
    public void close() {
        PosixIO.close(rootFd);
    }

    private int open(String rel, int flags) {
        int fd;
        if (openat2) {
            fd = openat2(rootFd, rel.isEmpty() ? "." : rel, flags, 0, RESOLVE);
        } else {
            try (Arena arena = Arena.ofConfined()) {
                fd = PosixIO.open(arena, rel.isEmpty() ? rootfs : rootfs + "/" + rel, flags, 0);
            }
        }
        if (fd < 0) return fail(Libc.errno());
        // With openat2 this cannot fail; on the fallback path it is what stops
        // a swapped-in symlink.
        String real = realPath(fd);
        if (real == null || !isInRoot(real)) {
            PosixIO.close(fd);
            throw new IllegalStateException("mount point " + real + " is outside the rootfs " + rootfs);
        }
        return fd;
    }

    private int fail(int err) {
        errno = err;
        return -1;
    }

    private boolean isInRoot(String path) {
        return path.equals(rootfs) || path.startsWith(rootfs.equals("/") ? "/" : rootfs + "/");
    }

    private String relative(String path) {
        String p = path;
        if (p.equals(rootfs)) return "";
        if (p.startsWith(rootfs + "/")) p = p.substring(rootfs.length());
        while (p.startsWith("/")) p = p.substring(1);
        while (p.endsWith("/")) p = p.substring(0, p.length() - 1);
        return p;
    }

    private static int openat2(int dirfd, String path, long flags, long mode, long resolve) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment how = open_how.allocate(arena);
            open_how.flags(how, flags);
            open_how.mode(how, mode);
            open_how.resolve(how, resolve);
            MemorySegment p = arena.allocateFrom(path);
            return (int) Libc.syscall(Constants.NR_openat2, dirfd, p.address(), how.address(),
                    open_how.sizeof(), 0);
        }
    }
}
