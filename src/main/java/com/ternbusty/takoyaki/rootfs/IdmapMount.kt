package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

/**
 * Linux 5.12+ id-mapped mounts.
 *
 *     tree_fd = open_tree(src_dir_fd, src_path, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)
 *     userns_fd = open(/proc/PID/ns/user)
 *     mount_setattr(tree_fd, "", AT_EMPTY_PATH, {attr_set = MOUNT_ATTR_IDMAP, userns_fd})
 *     move_mount(tree_fd, "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH)
 *
 * Requires CAP_SYS_ADMIN in the user namespace that owns the destination, plus a
 * separate user namespace fd whose mapping describes the desired uid/gid translation.
 *
 * This implementation is best-effort: callers that need it should pass a userns_fd
 * obtained from the spec's uidMappings (e.g. by spawning an unshared helper process
 * to install the map and then reading /proc/<helper>/ns/user). For now we expose the
 * low-level entry point so subsequent work can wire it into the mount loop.
 */
object IdmapMount {
    // Syscall numbers (same on x86_64 and aarch64 for these recent additions).
    private const val NR_open_tree = 428L
    private const val NR_move_mount = 429L
    private const val NR_mount_setattr = 442L

    private const val OPEN_TREE_CLONE = 0x1
    private const val OPEN_TREE_CLOEXEC = 0x80000
    private const val AT_EMPTY_PATH = 0x1000
    private const val AT_FDCWD = -100
    private const val MOVE_MOUNT_F_EMPTY_PATH = 0x4

    private const val MOUNT_ATTR_IDMAP = 0x00100000L
    private const val AT_RECURSIVE = 0x8000

    /** Open a clone of [source] as a detached mount tree, ready for setattr. */
    @JvmOverloads
    fun openTree(source: String, cloneRecursive: Boolean = false): Int {
        Arena.ofConfined().use { arena ->
            val path = arena.allocateFrom(source)
            var flags = OPEN_TREE_CLONE or OPEN_TREE_CLOEXEC
            if (cloneRecursive) flags = flags or AT_RECURSIVE
            val rc = Libc.syscall(NR_open_tree, AT_FDCWD.toLong(), path.address(), flags.toLong(), 0, 0)
            if (rc < 0) {
                Logger.debug("open_tree($source) failed: ${Libc.strerror(Libc.errno())}")
                return -1
            }
            return rc.toInt()
        }
    }

    /**
     * Apply MOUNT_ATTR_IDMAP using the given user namespace fd.
     * When [recursive] is true, AT_RECURSIVE is passed to mount_setattr
     * so the id-mapping applies to all submounts (ridmap behaviour).
     */
    @JvmOverloads
    fun setIdmap(treeFd: Int, usernsFd: Int, recursive: Boolean = false): Boolean {
        Arena.ofConfined().use { arena ->
            // struct mount_attr { u64 attr_set; u64 attr_clr; u64 propagation; u64 userns_fd; }
            val attr = arena.allocate(32)
            attr.set(ValueLayout.JAVA_LONG, 0, MOUNT_ATTR_IDMAP)
            attr.set(ValueLayout.JAVA_LONG, 8, 0L)
            attr.set(ValueLayout.JAVA_LONG, 16, 0L)
            attr.set(ValueLayout.JAVA_LONG, 24, usernsFd.toLong())
            val empty = arena.allocateFrom("")
            val flags = AT_EMPTY_PATH or (if (recursive) AT_RECURSIVE else 0)
            val rc = Libc.syscall(
                NR_mount_setattr, treeFd.toLong(), empty.address(),
                flags.toLong(), attr.address(), 32
            )
            if (rc != 0L) {
                Logger.warn("mount_setattr(IDMAP) failed: ${Libc.strerror(Libc.errno())}")
                return false
            }
            return true
        }
    }

    /** Move the detached tree to its final mount point. */
    fun moveMount(treeFd: Int, destination: String): Boolean {
        Arena.ofConfined().use { arena ->
            val empty = arena.allocateFrom("")
            val dst = arena.allocateFrom(destination)
            val rc = Libc.syscall(
                NR_move_mount, treeFd.toLong(), empty.address(),
                AT_FDCWD.toLong(), dst.address(), MOVE_MOUNT_F_EMPTY_PATH.toLong()
            )
            if (rc != 0L) {
                Logger.warn("move_mount -> $destination failed: ${Libc.strerror(Libc.errno())}")
                return false
            }
            return true
        }
    }

    /**
     * Convenience: open tree, apply id-map, then move to destination.
     *
     * @param recursive       pass AT_RECURSIVE to mount_setattr (ridmap)
     * @param cloneRecursive  pass AT_RECURSIVE to open_tree (rbind sources with submounts)
     */
    @JvmOverloads
    fun apply(
        source: String,
        usernsFd: Int,
        destination: String,
        recursive: Boolean = false,
        cloneRecursive: Boolean = false,
    ): Boolean {
        val tree = openTree(source, cloneRecursive)
        if (tree < 0) return false
        try {
            if (!setIdmap(tree, usernsFd, recursive)) return false
            return moveMount(tree, destination)
        } finally {
            PosixIO.close(tree)
        }
    }
}
