package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.foreign.Arena;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Create a temporary user namespace populated with the given uid/gid mappings,
 * return its /proc/<helper>/ns/user fd, and apply MOUNT_ATTR_IDMAP to a clone of the
 * source path before move-mounting it to the destination.
 *
 * IMPORTANT: this helper has TWO entry points.
 *
 * {@link #setupHostSide} is called from the takoyaki main process BEFORE forking
 * the bootstrap. It runs on the host (host pid namespace, host /proc) so it can
 * address its forked helper via host pids. The returned fd survives the fork +
 * execve and is then handed to the init via env var.
 *
 * {@link #apply} is the in-init path used when the setup wasn't done on the host
 * (it only works for non-userns containers; for userns containers /proc and pids
 * get out of sync and mount_setattr returns EPERM). Prefer the host-side path.
 */
public final class IdmapHelper {
    private IdmapHelper() {}

    /** Apply an id-mapped bind mount from {@code source} to {@code destination}. */
    public static boolean apply(Spec.Mount m, String destination) {
        return apply(m, destination, false, false);
    }

    /**
     * Apply an id-mapped bind mount.
     *
     * @param recursive      pass AT_RECURSIVE to mount_setattr (ridmap semantics)
     * @param cloneRecursive pass AT_RECURSIVE to open_tree so submounts of the
     *                       source are included (needed for rbind sources whose
     *                       subtrees contain earlier mounts from the same spec)
     */
    public static boolean apply(Spec.Mount m, String destination,
                                boolean recursive, boolean cloneRecursive) {
        if (m.uidMappings == null || m.uidMappings.isEmpty()) return false;
        int usernsFd = openMappedUserNs(m.uidMappings, m.gidMappings);
        if (usernsFd < 0) return false;
        try {
            return IdmapMount.apply(m.source, usernsFd, destination,
                    recursive, cloneRecursive);
        } finally {
            PosixIO.close(usernsFd);
        }
    }

    /**
     * Apply an idmap bind mount using a pre-prepared userns fd (passed in from the
     * main process via env). The fd was opened in the host's pid/user namespace,
     * survives fork+execve, and points to a userns whose uid_map/gid_map were
     * already written by the host-side main process.
     */
    public static boolean applyWithFd(Spec.Mount m, int usernsFd, String destination) {
        return applyWithFd(m, usernsFd, destination, false, false);
    }

    /**
     * Apply with pre-prepared fd.
     *
     * @param recursive      pass AT_RECURSIVE to mount_setattr (ridmap)
     * @param cloneRecursive pass AT_RECURSIVE to open_tree (rbind submounts)
     */
    public static boolean applyWithFd(Spec.Mount m, int usernsFd, String destination,
                                      boolean recursive, boolean cloneRecursive) {
        return IdmapMount.apply(m.source, usernsFd, destination,
                recursive, cloneRecursive);
    }

    /**
     * Host-side setup: spawn a helper process that unshares CLONE_NEWUSER, then
     * write uid_map/gid_map from this (parent) process via host /proc, open
     * /proc/<helper>/ns/user and return the fd. The helper exits once released.
     */
    public static int setupHostSide(List<Spec.IdMapping> uidMaps,
                                    List<Spec.IdMapping> gidMaps) {
        return openMappedUserNs(uidMaps, gidMaps);
    }

    /**
     * Spawn a helper process via ProcessBuilder that unshares CLONE_NEWUSER,
     * write the mappings to /proc/<helper>/uid_map and /proc/<helper>/gid_map
     * from this process, then open /proc/<helper>/ns/user.
     *
     * The helper is /proc/self/exe with _TAKOYAKI_IDMAP_HELPER set in its
     * environment. bootstrap.c's constructor intercepts this env var and
     * does unshare + stdout/stdin sync entirely in C, calling _exit(0)
     * before SubstrateVM ever starts. This avoids the safepoint deadlock
     * that occurs when forking from a multi-threaded SubstrateVM process.
     */
    private static int openMappedUserNs(List<Spec.IdMapping> uidMaps,
                                        List<Spec.IdMapping> gidMaps) {
        Process helper;
        try {
            ProcessBuilder pb = new ProcessBuilder("/proc/self/exe");
            pb.environment().put("_TAKOYAKI_IDMAP_HELPER", "1");
            pb.redirectError(ProcessBuilder.Redirect.INHERIT);
            helper = pb.start();
        } catch (IOException e) {
            Logger.warn("idmap helper process start failed: " + e.getMessage());
            return -1;
        }

        long pid = helper.pid();
        try (InputStream in = helper.getInputStream();
             OutputStream out = helper.getOutputStream()) {
            // Wait for the helper to signal that unshare(CLONE_NEWUSER) completed.
            int syncByte = in.read();
            if (syncByte != 1) {
                Logger.warn("idmap helper unshare(CLONE_NEWUSER) failed (sync=" + syncByte + ")");
                helper.destroyForcibly();
                return -1;
            }

            if (Logger.isDebugEnabled()) {
                try {
                    String helperLink = Files.readSymbolicLink(Path.of("/proc/" + pid + "/ns/user")).toString();
                    String myLink = Files.readSymbolicLink(Path.of("/proc/self/ns/user")).toString();
                    Logger.debug("idmap parent pid=" + ProcessHandle.current().pid()
                            + " helperPid=" + pid
                            + " helper=" + helperLink + " ours=" + myLink);
                    if (helperLink.equals(myLink)) {
                        Logger.warn("idmap helper userns same as ours (" + myLink + "); unshare lied");
                    }
                } catch (IOException ignored) {}
            }

            // Write maps from this process's privileged context.
            writeMappings(pid, uidMaps, "uid_map");
            writeMappings(pid, gidMaps, "gid_map");

            if (Logger.isDebugEnabled()) {
                try {
                    String uidMapContent = Files.readString(Path.of("/proc/" + pid + "/uid_map"));
                    String gidMapContent = Files.readString(Path.of("/proc/" + pid + "/gid_map"));
                    Logger.debug("idmap helper uid_map=" + uidMapContent.replace("\n", "|")
                            + " gid_map=" + gidMapContent.replace("\n", "|"));
                } catch (IOException e) {
                    Logger.warn("could not read back idmap helper maps: " + e.getMessage());
                }
            }

            // Open the helper's userns fd while it is still alive.
            int fd;
            try (Arena arena = Arena.ofConfined()) {
                fd = PosixIO.open(arena, "/proc/" + pid + "/ns/user", Constants.O_RDONLY, 0);
            }

            // Release the helper so it can _exit(0).
            out.write(1);
            out.flush();

            helper.waitFor();

            if (fd < 0) {
                Logger.warn("open helper userns fd failed");
            }
            return fd;
        } catch (IOException | InterruptedException e) {
            Logger.warn("idmap helper communication failed: " + e.getMessage());
            helper.destroyForcibly();
            return -1;
        }
    }

    /**
     * Write a userns map intended to drive mount_setattr(MOUNT_ATTR_IDMAP).
     *
     * The uid_map format is {@code "inside outside count"}. For an idmap userns
     * the kernel's make_vfsuid() calls from_kuid(idmap_userns, disk_kuid) which
     * uses map_id_up: it looks up disk_kuid in the OUTSIDE column and returns
     * the INSIDE value. So to make "disk uid 0 appear as containerID 100000"
     * with OCI mapping {containerID=0, hostID=100000} we write
     * {@code "containerID hostID size"} = {@code "0 100000 65536"} so that
     * INSIDE=containerID=0 and OUTSIDE=hostID=100000. Then map_id_up(disk_uid=0)
     * finds 0 in [outside=100000..165535]? No, that does not match for disk_uid=0.
     *
     * Actually: for an idmap mount the OCI spec semantics are that hostID is the
     * on-disk UID and containerID is what shows through the mount. Verified
     * empirically: the kernel's from_kuid maps disk UIDs via the OUTSIDE column
     * of the userns uid_map.  Writing "containerID hostID size" (= "0 100000
     * 65536") makes disk uid 0 appear as uid 100000 through the mount, matching
     * runc's behaviour.  This is the SAME direction as a process-attached userns.
     */
    private static void writeMappings(long pid, List<Spec.IdMapping> maps, String file) {
        if (maps == null || maps.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        for (Spec.IdMapping m : maps) {
            sb.append(m.containerID).append(' ')
              .append(m.hostID).append(' ')
              .append(m.size).append('\n');
        }
        try {
            Files.writeString(Path.of("/proc/" + pid + "/" + file), sb.toString());
        } catch (IOException e) {
            Logger.warn("write /proc/" + pid + "/" + file + " failed: " + e.getMessage());
        }
    }
}
