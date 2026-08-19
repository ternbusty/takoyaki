package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.SyscallHost;
import com.ternbusty.takoyaki.syscall.Syscalls;

import java.lang.foreign.Arena;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Create additional devices declared in spec.linux.devices.
 *
 * In a user namespace mknod(2) is typically denied; we fall back to bind-mounting
 * the host device file the same way the default /dev/null etc. are handled.
 */
public final class Devices {
    private Devices() {}

    public static void create(String rootfsPath, List<Spec.LinuxDevice> devices) {
        if (devices == null || devices.isEmpty()) return;
        Syscalls sc = SyscallHost.current();
        try (Arena arena = Arena.ofConfined()) {
            for (Spec.LinuxDevice d : devices) {
                if (d.path == null || d.type == null) continue;
                String target = rootfsPath + d.path;
                try { Files.createDirectories(Path.of(target).getParent()); }
                catch (Exception ignored) {}
                int typeBits = typeBits(d.type);
                if (typeBits == 0) { Logger.warn("unsupported device type: " + d.type); continue; }
                int mode = (d.fileMode == null ? 0666 : d.fileMode.intValue()) | typeBits;
                long dev = makedev(
                        d.major == null ? 0 : d.major.longValue(),
                        d.minor == null ? 0 : d.minor.longValue());

                int rc = sc.mknod(target, mode, dev);
                if (rc == 0) {
                    // mknod respects the umask, so a spec fileMode like 0660 lands
                    // as 0640 with the default 0022 umask. Re-chmod to the requested
                    // mode (the type bits aren't allowed in chmod, so mask them out).
                    try {
                        if (d.fileMode != null) {
                            Files.setPosixFilePermissions(Path.of(target),
                                    permsForMode(d.fileMode.intValue() & 0777));
                        }
                    } catch (Exception e) {
                        Logger.debug("chmod " + d.path + " failed: " + e.getMessage());
                    }
                    // Set ownership per spec (runc always chowns to the spec's uid/gid).
                    chownDevice(arena, target, d);
                    Logger.debug("mknod " + d.path + " (" + d.type + " " + d.major + ":" + d.minor + ")");
                    continue;
                }
                // mknod denied (e.g. user namespace) - fall back to bind mount from host.
                String hostPath = d.path;
                if (sc.access(hostPath, Constants.F_OK) != 0) {
                    Logger.debug("device " + d.path + " not on host either, skipping");
                    continue;
                }
                int fd = PosixIO.open(arena, target, Constants.O_RDWR | Constants.O_CREAT, 0666);
                if (fd >= 0) PosixIO.close(fd);
                if (sc.mount(hostPath, target, null, Constants.MS_BIND, null) != 0) {
                    Logger.debug("bind " + d.path + " from host failed: " + sc.strerror(sc.errno()));
                } else {
                    // Set ownership per spec even for bind-mounted devices.
                    chownDevice(arena, target, d);
                    Logger.debug("bind mounted " + d.path + " from host");
                }
            }
        }
    }

    /**
     * Translate the spec's device-type letter into the kernel's S_IF* type bits
     * that mknod(2) wants OR'd into the mode argument. Returns 0 for unknown
     * types so the caller can skip with a warning. Package-visible for tests.
     */
    static int typeBits(String type) {
        return switch (type) {
            case "c", "u" -> Constants.S_IFCHR;
            case "b"      -> Constants.S_IFBLK;
            case "p"      -> Constants.S_IFIFO;
            default       -> 0;
        };
    }

    /**
     * Translate the bottom 9 bits of a Unix mode word into the
     * PosixFilePermission set Files.setPosixFilePermissions wants.
     * Package-visible for tests.
     */
    static java.util.Set<java.nio.file.attribute.PosixFilePermission> permsForMode(int permBits) {
        java.util.Set<java.nio.file.attribute.PosixFilePermission> perms = new java.util.HashSet<>();
        if ((permBits & 0400) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OWNER_READ);
        if ((permBits & 0200) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
        if ((permBits & 0100) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE);
        if ((permBits & 0040) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.GROUP_READ);
        if ((permBits & 0020) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
        if ((permBits & 0010) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE);
        if ((permBits & 0004) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OTHERS_READ);
        if ((permBits & 0002) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
        if ((permBits & 0001) != 0) perms.add(java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE);
        return perms;
    }

    /**
     * Set uid/gid on a device node per the OCI spec entry.
     * runc always chowns to the spec's uid:gid (default 0:0).
     */
    private static void chownDevice(Arena arena, String path, Spec.LinuxDevice d) {
        int uid = d.uid == null ? 0 : d.uid.intValue();
        int gid = d.gid == null ? 0 : d.gid.intValue();
        if (Libc.chown(arena, path, uid, gid) != 0) {
            Logger.debug("chown " + path + " " + uid + ":" + gid
                    + " failed: " + Libc.strerror(Libc.errno()));
        }
    }

    /** Encode (major, minor) into a Linux dev_t (glibc convention). Package-visible for tests. */
    static long makedev(long major, long minor) {
        return ((major & 0xfffff000L) << 32)
             | ((major & 0x00000fffL) << 8)
             | ((minor & 0xffffff00L) << 12)
             | (minor & 0x000000ffL);
    }
}
