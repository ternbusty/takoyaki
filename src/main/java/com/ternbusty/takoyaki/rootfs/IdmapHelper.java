package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
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

    /**
     * Downcall handle for the C function {@code takoyaki_idmap_helper_fork}
     * defined in bootstrap.c.  The function forks a child that unshares
     * CLONE_NEWUSER and syncs via a socketpair, keeping all work in pure C
     * so that SubstrateVM's broken post-fork state (missing GC/signal
     * threads) never causes a safepoint deadlock.
     */
    private static final MethodHandle NATIVE_FORK;
    static {
        MethodHandle mh;
        try {
            mh = Linker.nativeLinker().downcallHandle(
                    SymbolLookup.loaderLookup()
                            .or(Linker.nativeLinker().defaultLookup())
                            .find("takoyaki_idmap_helper_fork")
                            .orElseThrow(() -> new UnsatisfiedLinkError(
                                    "takoyaki_idmap_helper_fork")),
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT));
        } catch (UnsatisfiedLinkError e) {
            // Should never happen: the symbol is in libbootstrap.a linked
            // with --whole-archive and exported via -rdynamic. The
            // defaultLookup() fallback uses dlsym(RTLD_DEFAULT) which
            // searches the main executable. Log and fall through so the
            // class still loads (the MethodHandle stays null and nativeFork
            // returns -1).
            System.err.println("WARNING: " + e.getMessage());
            mh = null;
        }
        NATIVE_FORK = mh;
    }

    private static int nativeFork(int parentFd, int childFd) {
        if (NATIVE_FORK == null) return -1;
        try {
            return (int) NATIVE_FORK.invokeExact(parentFd, childFd);
        } catch (Throwable t) {
            return -1;
        }
    }

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
     * Host-side setup: fork a helper, helper unshares CLONE_NEWUSER, parent (the
     * main takoyaki process) writes uid_map/gid_map to the helper via host pids,
     * parent opens /proc/&lt;helper&gt;/ns/user and returns the fd. The helper waits
     * forever and is implicitly killed when this process exits — we don't kill it
     * explicitly because the returned fd is what pins the userns alive.
     */
    public static int setupHostSide(List<Spec.IdMapping> uidMaps,
                                    List<Spec.IdMapping> gidMaps) {
        return openMappedUserNs(uidMaps, gidMaps);
    }

    /**
     * Spawn a helper child via fork+unshare(CLONE_NEWUSER), write the mappings to
     * /proc/<child>/uid_map and /proc/<child>/gid_map from the parent, then keep
     * /proc/<child>/ns/user open in the parent. The child blocks on a pipe until
     * the parent has finished.
     */
    private static int openMappedUserNs(List<Spec.IdMapping> uidMaps,
                                        List<Spec.IdMapping> gidMaps) {
        try (Arena arena = Arena.ofConfined()) {
            int[] sync = new int[2];
            if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, sync) < 0) {
                Logger.warn("idmap helper socketpair failed: " + Libc.strerror(Libc.errno()));
                return -1;
            }
            // The child-side work (close, unshare, sync write/read, _exit)
            // is done entirely in C by takoyaki_idmap_helper_fork().  After
            // fork() from a multi-threaded SubstrateVM process the child has
            // only 1 thread and the GC/signal threads are gone.  Any Java
            // allocation would trigger a GC safepoint that waits forever for
            // those dead threads (the ARM CI 1 ms nanosleep spin).
            int pid = nativeFork(sync[0], sync[1]);
            if (pid < 0) {
                Logger.warn("idmap helper fork failed: " + Libc.strerror(Libc.errno()));
                return -1;
            }
            PosixIO.close(sync[1]);
            try (Arena a2 = Arena.ofConfined()) {
                byte[] one = new byte[1];
                PosixIO.read(a2, sync[0], one);
                if (one[0] != 1) {
                    Logger.warn("idmap helper unshare(CLONE_NEWUSER) failed; aborting idmap");
                    PosixIO.close(sync[0]);
                    return -1;
                }
            }
            // Sanity-check: the helper's userns must NOT be our own (the kernel rejects
            // mount_setattr(IDMAP) with EPERM if userns_fd == init_user_ns).
            if (Logger.isDebugEnabled()) {
                try {
                    String helperLink = Files.readSymbolicLink(Path.of("/proc/" + pid + "/ns/user")).toString();
                    String myLink = Files.readSymbolicLink(Path.of("/proc/self/ns/user")).toString();
                    Logger.debug("idmap parent pid=" + Libc.getpid() + " childPid=" + pid
                            + " helper=" + helperLink + " ours=" + myLink);
                    if (helperLink.equals(myLink)) {
                        Logger.warn("idmap helper userns same as ours (" + myLink + "); unshare lied");
                    }
                } catch (IOException ignored) {}
            }
            // Write maps from the parent's privileged context.
            writeMappings(pid, uidMaps, "uid_map");
            writeMappings(pid, gidMaps, "gid_map");
            // Verify what actually landed in /proc/<helper>/uid_map.
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
            int fd = PosixIO.open(arena, "/proc/" + pid + "/ns/user", Constants.O_RDONLY, 0);
            // Release helper child.
            try (Arena a2 = Arena.ofConfined()) {
                byte[] go = new byte[]{1};
                PosixIO.write(a2, sync[0], go);
            }
            PosixIO.close(sync[0]);
            if (fd < 0) {
                Logger.warn("open helper userns fd failed: " + Libc.strerror(Libc.errno()));
            }
            return fd;
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
    private static void writeMappings(int pid, List<Spec.IdMapping> maps, String file) {
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
