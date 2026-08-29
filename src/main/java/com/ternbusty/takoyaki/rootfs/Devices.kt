package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.syscall.SyscallHost
import java.lang.foreign.Arena
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * Create additional devices declared in spec.linux.devices.
 *
 * In a user namespace mknod(2) is typically denied; we fall back to bind-mounting
 * the host device file the same way the default /dev/null etc. are handled.
 */
object Devices {

    fun create(rootfsPath: String, devices: List<LinuxDevice>?) {
        if (devices.isNullOrEmpty()) return
        val sc = SyscallHost.current()
        Arena.ofConfined().use { arena ->
            for (d in devices) {
                if (d.path == null || d.type == null) continue
                val target = rootfsPath + d.path
                try {
                    Files.createDirectories(Path.of(target).parent)
                } catch (_: Exception) {
                }
                val devType = d.type ?: continue
                val typeBits = typeBits(devType)
                if (typeBits == 0) {
                    Logger.warn("unsupported device type: ${d.type}")
                    continue
                }
                val mode = (d.fileMode?.toInt() ?: 0x1b6 /* 0666 */) or typeBits
                val dev = makedev(
                    d.major?.toLong() ?: 0L,
                    d.minor?.toLong() ?: 0L
                )

                val rc = sc.mknod(target, mode, dev)
                if (rc == 0) {
                    // mknod respects the umask, so a spec fileMode like 0660 lands
                    // as 0640 with the default 0022 umask. Re-chmod to the requested
                    // mode (the type bits aren't allowed in chmod, so mask them out).
                    val fm = d.fileMode
                    if (fm != null) {
                        try {
                            Files.setPosixFilePermissions(
                                Path.of(target),
                                permsForMode(fm.toInt() and 0x1ff /* 0777 */)
                            )
                        } catch (e: Exception) {
                            Logger.debug("chmod ${d.path} failed: ${e.message}")
                        }
                    }
                    // Set ownership per spec (runc always chowns to the spec's uid/gid).
                    chownDevice(arena, target, d)
                    Logger.debug("mknod ${d.path} (${d.type} ${d.major}:${d.minor})")
                    continue
                }
                // mknod denied (e.g. user namespace) - fall back to bind mount from host.
                val hostPath = d.path ?: continue
                if (sc.access(hostPath, Constants.F_OK) != 0) {
                    Logger.debug("device ${d.path} not on host either, skipping")
                    continue
                }
                val fd = PosixIO.open(arena, target, Constants.O_RDWR or Constants.O_CREAT, 0x1b6 /* 0666 */)
                if (fd >= 0) PosixIO.close(fd)
                if (sc.mount(hostPath, target, null, Constants.MS_BIND, null) != 0) {
                    Logger.debug("bind ${d.path} from host failed: ${sc.strerror(sc.errno())}")
                } else {
                    // Set ownership per spec even for bind-mounted devices.
                    chownDevice(arena, target, d)
                    Logger.debug("bind mounted ${d.path} from host")
                }
            }
        }
    }

    /**
     * Translate the spec's device-type letter into the kernel's S_IF* type bits
     * that mknod(2) wants OR'd into the mode argument. Returns 0 for unknown
     * types so the caller can skip with a warning. Package-visible for tests.
     */
    internal fun typeBits(type: String): Int = when (type) {
        "c", "u" -> Constants.S_IFCHR
        "b" -> Constants.S_IFBLK
        "p" -> Constants.S_IFIFO
        else -> 0
    }

    /**
     * Translate the bottom 9 bits of a Unix mode word into the
     * PosixFilePermission set Files.setPosixFilePermissions wants.
     * Package-visible for tests.
     */
    internal fun permsForMode(permBits: Int): Set<PosixFilePermission> {
        val perms = mutableSetOf<PosixFilePermission>()
        if (permBits and 0x100 /* 0400 */ != 0) perms += PosixFilePermission.OWNER_READ
        if (permBits and 0x80  /* 0200 */ != 0) perms += PosixFilePermission.OWNER_WRITE
        if (permBits and 0x40  /* 0100 */ != 0) perms += PosixFilePermission.OWNER_EXECUTE
        if (permBits and 0x20  /* 0040 */ != 0) perms += PosixFilePermission.GROUP_READ
        if (permBits and 0x10  /* 0020 */ != 0) perms += PosixFilePermission.GROUP_WRITE
        if (permBits and 0x8   /* 0010 */ != 0) perms += PosixFilePermission.GROUP_EXECUTE
        if (permBits and 0x4   /* 0004 */ != 0) perms += PosixFilePermission.OTHERS_READ
        if (permBits and 0x2   /* 0002 */ != 0) perms += PosixFilePermission.OTHERS_WRITE
        if (permBits and 0x1   /* 0001 */ != 0) perms += PosixFilePermission.OTHERS_EXECUTE
        return perms
    }

    /**
     * Set uid/gid on a device node per the OCI spec entry.
     * runc always chowns to the spec's uid:gid (default 0:0).
     */
    private fun chownDevice(arena: Arena, path: String, d: LinuxDevice) {
        val uid = d.uid?.toInt() ?: 0
        val gid = d.gid?.toInt() ?: 0
        if (Libc.chown(arena, path, uid, gid) != 0) {
            Logger.debug("chown $path $uid:$gid failed: ${Libc.strerror(Libc.errno())}")
        }
    }

    /** Encode (major, minor) into a Linux dev_t (glibc convention). Package-visible for tests. */
    internal fun makedev(major: Long, minor: Long): Long =
        ((major and 0xfffff000L) shl 32) or
        ((major and 0x00000fffL) shl 8) or
        ((minor and 0xffffff00L) shl 12) or
        (minor and 0x000000ffL)
}
