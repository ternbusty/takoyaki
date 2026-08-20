package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Linux 5.12+ id-mapped mounts.
 *
 *   tree_fd = open_tree(src_dir_fd, src_path, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)
 *   userns_fd = open(/proc/PID/ns/user)
 *   mount_setattr(tree_fd, "", AT_EMPTY_PATH, {attr_set = MOUNT_ATTR_IDMAP, userns_fd})
 *   move_mount(tree_fd, "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH)
 *
 * Requires CAP_SYS_ADMIN in the user namespace that owns the destination, plus a
 * separate user namespace fd whose mapping describes the desired uid/gid translation.
 *
 * This implementation is best-effort: callers that need it should pass a userns_fd
 * obtained from the spec's uidMappings (e.g. by spawning an unshared helper process
 * to install the map and then reading /proc/<helper>/ns/user). For now we expose the
 * low-level entry point so subsequent work can wire it into the mount loop.
 */
public final class IdmapMount {
    // Syscall numbers (same on x86_64 and aarch64 for these recent additions).
    private static final long NR_open_tree     = 428L;
    private static final long NR_move_mount    = 429L;
    private static final long NR_mount_setattr = 442L;

    private static final int OPEN_TREE_CLONE        = 0x1;
    private static final int OPEN_TREE_CLOEXEC      = 0x80000;
    private static final int AT_EMPTY_PATH          = 0x1000;
    private static final int AT_FDCWD               = -100;
    private static final int MOVE_MOUNT_F_EMPTY_PATH = 0x4;

    private static final long MOUNT_ATTR_IDMAP = 0x00100000L;
    private static final int AT_RECURSIVE     = 0x8000;

    private IdmapMount() {}

    /** Open a clone of {@code source} as a detached mount tree, ready for setattr. */
    public static int openTree(String source) {
        return openTree(source, false);
    }

    /**
     * Open a clone of {@code source} as a detached mount tree.
     * When {@code cloneRecursive} is true, AT_RECURSIVE is passed so
     * the clone captures all submounts (needed for rbind sources that
     * have overlaid mounts from earlier spec entries).
     */
    public static int openTree(String source, boolean cloneRecursive) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment path = arena.allocateFrom(source);
            int flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
            if (cloneRecursive) flags |= AT_RECURSIVE;
            long rc = Libc.syscall(NR_open_tree, AT_FDCWD, path.address(),
                    flags, 0, 0);
            if (rc < 0) {
                Logger.debug("open_tree(" + source + ") failed: " + Libc.strerror(Libc.errno()));
                return -1;
            }
            return (int) rc;
        }
    }

    /** Apply MOUNT_ATTR_IDMAP using the given user namespace fd. */
    public static boolean setIdmap(int treeFd, int usernsFd) {
        return setIdmap(treeFd, usernsFd, false);
    }

    /**
     * Apply MOUNT_ATTR_IDMAP using the given user namespace fd.
     * When {@code recursive} is true, AT_RECURSIVE is passed to mount_setattr
     * so the id-mapping applies to all submounts (ridmap behaviour).
     */
    public static boolean setIdmap(int treeFd, int usernsFd, boolean recursive) {
        try (Arena arena = Arena.ofConfined()) {
            // struct mount_attr { u64 attr_set; u64 attr_clr; u64 propagation; u64 userns_fd; }
            MemorySegment attr = arena.allocate(32);
            attr.set(ValueLayout.JAVA_LONG, 0, MOUNT_ATTR_IDMAP);
            attr.set(ValueLayout.JAVA_LONG, 8, 0L);
            attr.set(ValueLayout.JAVA_LONG, 16, 0L);
            attr.set(ValueLayout.JAVA_LONG, 24, (long) usernsFd);
            MemorySegment empty = arena.allocateFrom("");
            int flags = AT_EMPTY_PATH | (recursive ? AT_RECURSIVE : 0);
            long rc = Libc.syscall(NR_mount_setattr, treeFd, empty.address(),
                    flags, attr.address(), 32);
            if (rc != 0) {
                Logger.warn("mount_setattr(IDMAP) failed: " + Libc.strerror(Libc.errno()));
                return false;
            }
            return true;
        }
    }

    /** Move the detached tree to its final mount point. */
    public static boolean moveMount(int treeFd, String destination) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment empty = arena.allocateFrom("");
            MemorySegment dst = arena.allocateFrom(destination);
            long rc = Libc.syscall(NR_move_mount, treeFd, empty.address(),
                    AT_FDCWD, dst.address(), MOVE_MOUNT_F_EMPTY_PATH);
            if (rc != 0) {
                Logger.warn("move_mount → " + destination + " failed: " + Libc.strerror(Libc.errno()));
                return false;
            }
            return true;
        }
    }

    /** Convenience: open tree, apply id-map, then move to destination. */
    public static boolean apply(String source, int usernsFd, String destination) {
        return apply(source, usernsFd, destination, false, false);
    }

    /** Convenience: open tree, apply id-map (optionally recursive), then move to destination. */
    public static boolean apply(String source, int usernsFd, String destination,
                                boolean recursive) {
        return apply(source, usernsFd, destination, recursive, false);
    }

    /**
     * Convenience: open tree, apply id-map, then move to destination.
     *
     * @param recursive    pass AT_RECURSIVE to mount_setattr (ridmap)
     * @param cloneRecursive pass AT_RECURSIVE to open_tree (rbind sources with submounts)
     */
    public static boolean apply(String source, int usernsFd, String destination,
                                boolean recursive, boolean cloneRecursive) {
        int tree = openTree(source, cloneRecursive);
        if (tree < 0) return false;
        try {
            if (!setIdmap(tree, usernsFd, recursive)) return false;
            return moveMount(tree, destination);
        } finally {
            PosixIO.close(tree);
        }
    }
}
