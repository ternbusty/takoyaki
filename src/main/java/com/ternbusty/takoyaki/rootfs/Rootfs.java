package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.SyscallHost;
import com.ternbusty.takoyaki.syscall.Syscalls;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class Rootfs {
    private Rootfs() {}

    // Default /dev entries that get bind-mounted from the host at container
    // start-up. Matches the set every OCI runtime provides by default — the
    // audit against runc / youki flagged /dev/console as missing here.
    // /dev/console is typically 0600 root:root on the host, so the bind
    // silently no-ops in rootless mode (bindDevice logs and moves on).
    private static final String[] DEVICES =
            {"null", "zero", "random", "urandom", "tty", "full", "console"};

    public static void prepare(String rootfsPath, Spec spec) {
        prepare(rootfsPath, spec, java.util.Collections.emptyMap());
    }

    public static void prepare(String rootfsPath, Spec spec,
                               java.util.Map<String, Integer> idmapFds) {
        try (Arena arena = Arena.ofConfined()) {
            if (PosixIO.access(arena, rootfsPath, Constants.F_OK) != 0) {
                throw new RuntimeException("rootfs not found: " + rootfsPath);
            }

            // Always set / to slave|rec BEFORE pivot_root. pivot_root requires the
            // new root (and its parent) not to be MS_SHARED. spec.linux.rootfsPropagation
            // is applied AFTER pivot_root, see pivot().
            Logger.debug("set / propagation to slave");
            if (Libc.mount(arena, null, "/", null,
                    Constants.MS_SLAVE | Constants.MS_REC, null) != 0) {
                Logger.warn("mount / MS_SLAVE failed: " + Libc.strerror(Libc.errno()));
            }

            // Always bind-mount the rootfs to itself so it becomes its own mount,
            // which pivot_root requires. For overlay rootfs (containerd) this is also
            // important to detach the mount from the host's shared propagation.
            Logger.debug("bind mount rootfs: " + rootfsPath);
            if (Libc.mount(arena, rootfsPath, rootfsPath, null,
                    Constants.MS_BIND | Constants.MS_REC, null) != 0) {
                throw new RuntimeException("bind mount rootfs failed: " + Libc.strerror(Libc.errno()));
            }
            // pivot_root requires the new root and its parent to not have MS_SHARED
            // propagation. Force the rootfs mount to private so it satisfies the rule
            // regardless of what the host had.
            if (Libc.mount(arena, null, rootfsPath, null,
                    Constants.MS_PRIVATE, null) != 0) {
                Logger.debug("set rootfs private failed: " + Libc.strerror(Libc.errno()));
            }
            // Remount rootfs with MS_NOSUID so setuid binaries inside the container
            // can't gain extra privileges through the host's mount layer.
            if (Libc.mount(arena, null, rootfsPath, null,
                    Constants.MS_BIND | Constants.MS_REMOUNT | Constants.MS_NOSUID, null) != 0) {
                Logger.debug("rootfs MS_NOSUID remount failed: " + Libc.strerror(Libc.errno()));
            } else {
                Logger.debug("rootfs marked MS_NOSUID");
            }

            mountProc(arena, rootfsPath);
            mountDev(arena, rootfsPath);
            mountSys(arena, rootfsPath, spec);

            if (spec.mounts != null) {
                applyOciMounts(arena, rootfsPath, spec.mounts, idmapFds);
            }
        }
    }

    private static void mountProc(Arena arena, String rootfsPath) {
        String p = rootfsPath + "/proc";
        if (PosixIO.access(arena, p, Constants.F_OK) != 0) {
            try { Files.createDirectories(Path.of(p)); }
            catch (IOException e) { Logger.warn("mkdir proc: " + e.getMessage()); return; }
        }
        if (Libc.mount(arena, "proc", p, "proc",
                Constants.MS_NOSUID | Constants.MS_NODEV | Constants.MS_NOEXEC, null) != 0) {
            Logger.warn("mount /proc: " + Libc.strerror(Libc.errno()));
        } else {
            Logger.debug("mounted /proc");
        }
    }

    private static void mountDev(Arena arena, String rootfsPath) {
        String dev = rootfsPath + "/dev";
        if (PosixIO.access(arena, dev, Constants.F_OK) != 0) {
            try { Files.createDirectories(Path.of(dev)); }
            catch (IOException e) { Logger.warn("mkdir dev: " + e.getMessage()); return; }
        }
        if (Libc.mount(arena, "tmpfs", dev, "tmpfs",
                Constants.MS_NOSUID | Constants.MS_NOEXEC, "mode=755") != 0) {
            Logger.warn("mount /dev tmpfs: " + Libc.strerror(Libc.errno()));
            return;
        }
        Logger.debug("mounted /dev (tmpfs)");
        for (String d : DEVICES) bindDevice(arena, dev, d);

        // OCI default mount order under /dev is pts → shm → mqueue; matching it
        // makes runtime-tools' "found in order" check pass since the spec lists
        // them in that order and the test scans /proc/self/mountinfo forward-only.
        String pts = dev + "/pts";
        try { Files.createDirectories(Path.of(pts)); } catch (IOException ignored) {}
        if (Libc.mount(arena, "devpts", pts, "devpts",
                Constants.MS_NOSUID | Constants.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620") != 0) {
            Logger.debug("mount /dev/pts: " + Libc.strerror(Libc.errno()));
        }

        String shm = dev + "/shm";
        try { Files.createDirectories(Path.of(shm)); } catch (IOException ignored) {}
        if (Libc.mount(arena, "shm", shm, "tmpfs",
                Constants.MS_NOSUID | Constants.MS_NODEV | Constants.MS_NOEXEC,
                "mode=1777,size=65536k") != 0) {
            Logger.warn("mount /dev/shm: " + Libc.strerror(Libc.errno()));
        } else {
            Logger.debug("mounted /dev/shm");
        }

        // /dev/mqueue (OCI default mount). Required by runtime-tools default test.
        String mqueue = dev + "/mqueue";
        try { Files.createDirectories(Path.of(mqueue)); } catch (IOException ignored) {}
        if (Libc.mount(arena, "mqueue", mqueue, "mqueue",
                Constants.MS_NOSUID | Constants.MS_NODEV | Constants.MS_NOEXEC, null) != 0) {
            Logger.debug("mount /dev/mqueue: " + Libc.strerror(Libc.errno()));
        } else {
            Logger.debug("mounted /dev/mqueue");
        }

        // OCI default symlinks under /dev that runtime-tools verifies.
        try {
            Path devPath = Path.of(dev);
            // /dev/ptmx -> pts/ptmx
            Path ptmx = devPath.resolve("ptmx");
            if (!Files.exists(ptmx, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createSymbolicLink(ptmx, Path.of("pts/ptmx"));
            }
            // /dev/fd -> /proc/self/fd
            Path fd = devPath.resolve("fd");
            if (!Files.exists(fd, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createSymbolicLink(fd, Path.of("/proc/self/fd"));
            }
            // /dev/stdin -> /proc/self/fd/0
            Path stdin = devPath.resolve("stdin");
            if (!Files.exists(stdin, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createSymbolicLink(stdin, Path.of("/proc/self/fd/0"));
            }
            // /dev/stdout -> /proc/self/fd/1
            Path stdout = devPath.resolve("stdout");
            if (!Files.exists(stdout, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createSymbolicLink(stdout, Path.of("/proc/self/fd/1"));
            }
            // /dev/stderr -> /proc/self/fd/2
            Path stderr = devPath.resolve("stderr");
            if (!Files.exists(stderr, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createSymbolicLink(stderr, Path.of("/proc/self/fd/2"));
            }
            Logger.debug("created /dev default symlinks");
        } catch (IOException e) {
            Logger.debug("dev symlinks: " + e.getMessage());
        }
    }

    private static void bindDevice(Arena arena, String devPath, String name) {
        String target = devPath + "/" + name;
        int fd = PosixIO.open(arena, target, Constants.O_RDWR | Constants.O_CREAT, 0666);
        if (fd >= 0) PosixIO.close(fd);
        else if (Libc.errno() != Constants.EEXIST) {
            Logger.warn("create " + target + ": " + Libc.strerror(Libc.errno()));
            return;
        }
        if (Libc.mount(arena, "/dev/" + name, target, null,
                Constants.MS_BIND, null) != 0) {
            if (Libc.errno() != Constants.EBUSY) {
                Logger.warn("bind /dev/" + name + ": " + Libc.strerror(Libc.errno()));
            }
        } else {
            Logger.debug("bind mounted /dev/" + name);
        }
    }

    private static void mountSys(Arena arena, String rootfsPath, Spec spec) {
        String sys = rootfsPath + "/sys";
        if (PosixIO.access(arena, sys, Constants.F_OK) != 0) {
            try { Files.createDirectories(Path.of(sys)); }
            catch (IOException e) { Logger.warn("mkdir sys: " + e.getMessage()); return; }
        }
        long flags = Constants.MS_NOSUID | Constants.MS_NODEV | Constants.MS_NOEXEC | Constants.MS_RDONLY;
        if (Libc.mount(arena, "sysfs", sys, "sysfs", flags, null) != 0) {
            int e = Libc.errno();
            if (e == Constants.EPERM) {
                Logger.debug("sysfs mount EPERM (user ns?), bind from host /sys");
                if (Libc.mount(arena, "/sys", sys, null,
                        Constants.MS_BIND | Constants.MS_REC, null) != 0) {
                    Logger.warn("bind /sys: " + Libc.strerror(Libc.errno()));
                }
            } else {
                Logger.warn("mount /sys: " + Libc.strerror(e));
            }
        } else {
            Logger.debug("mounted /sys");
        }

        // /sys/fs/cgroup
        String cg = sys + "/fs/cgroup";
        try { Files.createDirectories(Path.of(cg)); } catch (IOException ignored) {}
        String containerCgPath = spec != null && spec.linux != null && spec.linux.cgroupsPath != null
                ? (spec.linux.cgroupsPath.startsWith("/") ? spec.linux.cgroupsPath
                                                          : "/" + spec.linux.cgroupsPath)
                : readContainerCgroupPath();
        if (containerCgPath != null) {
            String src = "/sys/fs/cgroup" + containerCgPath;
            if (PosixIO.access(arena, src, Constants.F_OK) == 0) {
                if (Libc.mount(arena, src, cg, null,
                        Constants.MS_BIND | Constants.MS_REC, null) == 0) {
                    Libc.mount(arena, null, cg, null,
                            Constants.MS_BIND | Constants.MS_REMOUNT | Constants.MS_RDONLY
                                    | Constants.MS_NOSUID | Constants.MS_NODEV | Constants.MS_NOEXEC,
                            null);
                    Logger.debug("bound /sys/fs/cgroup from " + src);
                } else {
                    Logger.warn("bind /sys/fs/cgroup from " + src + ": " + Libc.strerror(Libc.errno()));
                }
            } else {
                Logger.debug("cgroup source " + src + " does not exist (yet)");
            }
        }
    }

    private static String readContainerCgroupPath() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/cgroup"))) {
                if (line.startsWith("0::")) {
                    String p = line.substring(3).trim();
                    return p.isEmpty() ? null : p;
                }
            }
        } catch (IOException ignored) {}
        return null;
    }

    private static boolean isMountPoint(String path) {
        try {
            Path p = Path.of(path);
            Path parent = p.getParent();
            if (parent == null) return true;
            return Files.getFileStore(p).equals(Files.getFileStore(parent)) ? false : true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Apply spec.mounts in order. Package-visible so the unit test can drive
     * this directly against a RecordingSyscalls fake — the previous private
     * signature meant this loop was only reachable via the full Rootfs.prepare
     * path which can't be unit-tested.
     *
     * The Arena parameter is retained for source compatibility with the old
     * call site but is no longer used; Syscalls implementations manage their
     * own Arenas internally.
     */
    static void applyOciMounts(Arena arena, String rootfsPath, List<Spec.Mount> mounts,
                               java.util.Map<String, Integer> idmapFds) {
        Syscalls sc = SyscallHost.current();
        for (Spec.Mount m : mounts) {
            if (m.destination == null) continue;
            // skip already-handled paths
            if (m.destination.equals("/proc") || m.destination.equals("/dev")
                || m.destination.equals("/sys") || m.destination.equals("/dev/shm")
                || m.destination.equals("/dev/pts") || m.destination.equals("/dev/mqueue")
                || m.destination.equals("/sys/fs/cgroup")) continue;
            String target = rootfsPath + m.destination;
            String type = m.type != null ? m.type : "none";
            MountOptions.Parsed parsed = MountOptions.parse(m.options);
            long flags = parsed.flags;
            long propagation = parsed.propagation;
            String data = parsed.data;
            boolean isBind = parsed.isBind;
            try { Files.createDirectories(Path.of(target)); } catch (IOException ignored) {}

            // Id-mapped mounts: if uidMappings/gidMappings are present we route the
            // bind through open_tree + mount_setattr(MOUNT_ATTR_IDMAP) + move_mount.
            // Prefer the host-prepared fd that CreateCommand stashed in idmapFds —
            // the in-init fork+unshare path doesn't work inside the container's
            // pid namespace because /proc shows host pids but our forked helper is
            // addressed via container-local pids.
            if (m.uidMappings != null && !m.uidMappings.isEmpty() && isBind) {
                Integer prepFd = idmapFds.get(m.destination);
                boolean done;
                if (prepFd != null) {
                    done = IdmapHelper.applyWithFd(m, prepFd, target);
                    if (done) Logger.debug("idmap mounted " + m.destination
                            + " using host-prepared fd " + prepFd);
                } else {
                    done = IdmapHelper.apply(m, target);
                    if (done) Logger.debug("idmap mounted " + m.destination
                            + " using in-init helper");
                }
                if (done) continue;
                Logger.warn("idmap mount failed for " + m.destination + ", falling back to plain bind");
            }

            int rc = sc.mount(m.source, target, isBind ? null : type, flags, data);
            if (rc != 0) {
                Logger.debug("optional mount " + m.destination + " failed: "
                        + sc.strerror(sc.errno()));
                continue;
            }
            Logger.debug("mounted " + m.destination + " (type=" + type + ")");
            // bind mounts ignore MS_RDONLY (and other access flags) on the initial
            // mount; the kernel just bind-attaches the source as-is. A second
            // MS_BIND|MS_REMOUNT with the desired flags is required to actually
            // enforce read-only / nosuid / nodev / noexec on the bind.
            if (isBind && (flags & (Constants.MS_RDONLY | Constants.MS_NOSUID
                    | Constants.MS_NODEV | Constants.MS_NOEXEC)) != 0) {
                long remountFlags = Constants.MS_BIND | Constants.MS_REMOUNT
                        | (flags & (Constants.MS_RDONLY | Constants.MS_NOSUID
                                  | Constants.MS_NODEV | Constants.MS_NOEXEC
                                  | Constants.MS_NOATIME | Constants.MS_RELATIME
                                  | Constants.MS_STRICTATIME | Constants.MS_NOSYMFOLLOW));
                if (sc.mount(null, target, null, remountFlags, null) != 0) {
                    Logger.debug("bind remount with access flags on " + m.destination
                            + " failed: " + sc.strerror(sc.errno()));
                }
            }
            // Apply per-mount propagation if requested. propagation flag has to be set
            // alone via a second mount() call.
            if (propagation != 0) {
                if (sc.mount(null, target, null, propagation, null) != 0) {
                    Logger.debug("propagation set on " + m.destination + " failed: "
                            + sc.strerror(sc.errno()));
                }
            }
        }
    }

    public static void pivot(String newRoot) {
        pivot(newRoot, null);
    }

    public static void pivot(String newRoot, String rootfsPropagation) {
        try (Arena arena = Arena.ofConfined()) {
            Logger.debug("pivot_root to " + newRoot);
            int newrootFd = PosixIO.open(arena, newRoot,
                    Constants.O_DIRECTORY | Constants.O_RDONLY, 0);
            if (newrootFd < 0) {
                throw new RuntimeException("open " + newRoot + ": " + Libc.strerror(Libc.errno()));
            }
            try {
                if (Libc.pivotRoot(arena, newRoot, newRoot) != 0) {
                    throw new RuntimeException("pivot_root: " + Libc.strerror(Libc.errno()));
                }
                if (Libc.mount(arena, null, "/", null,
                        Constants.MS_SLAVE | Constants.MS_REC, null) != 0) {
                    Logger.warn("remount / as slave failed: " + Libc.strerror(Libc.errno()));
                }
                if (Libc.umount2(arena, "/", Constants.MNT_DETACH) != 0) {
                    Logger.warn("umount2 / failed: " + Libc.strerror(Libc.errno()));
                }
                if (PosixIO.fchdir(newrootFd) != 0) {
                    throw new RuntimeException("fchdir: " + Libc.strerror(Libc.errno()));
                }
            } finally {
                PosixIO.close(newrootFd);
            }
            if (Libc.chdir(arena, "/") != 0) {
                throw new RuntimeException("chdir /: " + Libc.strerror(Libc.errno()));
            }
            // Apply spec.linux.rootfsPropagation to the new "/" — this is the
            // user-visible propagation mode inside the container. It has to
            // happen post-pivot because pivot_root rejects MS_SHARED on the
            // new root and its parent.
            if (rootfsPropagation != null) {
                long prop = switch (rootfsPropagation) {
                    case "shared"      -> Constants.MS_SHARED;
                    case "rshared"     -> Constants.MS_SHARED | Constants.MS_REC;
                    case "slave"       -> Constants.MS_SLAVE;
                    case "rslave"      -> Constants.MS_SLAVE | Constants.MS_REC;
                    case "private"     -> Constants.MS_PRIVATE;
                    case "rprivate"    -> Constants.MS_PRIVATE | Constants.MS_REC;
                    case "unbindable"  -> Constants.MS_UNBINDABLE;
                    case "runbindable" -> Constants.MS_UNBINDABLE | Constants.MS_REC;
                    default            -> 0L;
                };
                if (prop != 0) {
                    if (Libc.mount(arena, null, "/", null, prop, null) != 0) {
                        Logger.warn("set / to " + rootfsPropagation + " failed: "
                                + Libc.strerror(Libc.errno()));
                    } else {
                        Logger.debug("/ propagation set to " + rootfsPropagation);
                    }
                }
            }
            Logger.debug("pivot_root completed");
        }
    }

    public static void setRootReadonly() {
        try (Arena arena = Arena.ofConfined()) {
            // Preserve MS_NOSUID we set earlier — MS_REMOUNT replaces the flag set
            // wholesale, so we must include every flag we want to keep on.
            long flags = Constants.MS_BIND | Constants.MS_REMOUNT
                    | Constants.MS_RDONLY | Constants.MS_NOSUID;
            if (Libc.mount(arena, null, "/", null, flags, null) != 0) {
                Logger.warn("remount / readonly failed: " + Libc.strerror(Libc.errno()));
            } else {
                Logger.debug("/ set readonly+nosuid");
            }
        }
    }

    /**
     * Mask sensitive paths by bind-mounting /dev/null over files and a tmpfs over
     * directories. Used to hide /proc/kcore etc.
     */
    public static void maskPaths(List<String> paths) {
        if (paths == null) return;
        Syscalls sc = SyscallHost.current();
        for (String p : paths) {
            int rc = sc.mount("/dev/null", p, null, Constants.MS_BIND, null);
            if (rc == 0) {
                Logger.debug("masked " + p + " with /dev/null");
                continue;
            }
            int err = sc.errno();
            if (err == Constants.ENOENT) continue; // skip nonexistent
            // Likely a directory — mask with tmpfs.
            rc = sc.mount("tmpfs", p, "tmpfs", Constants.MS_RDONLY, null);
            if (rc != 0) {
                Logger.debug("mask " + p + " failed: " + sc.strerror(sc.errno()));
            } else {
                Logger.debug("masked " + p + " with tmpfs");
            }
        }
    }

    /** Bind-remount each path read-only. Used for /proc/bus, /proc/sys etc. */
    public static void readonlyRemount(List<String> paths) {
        if (paths == null) return;
        Syscalls sc = SyscallHost.current();
        for (String p : paths) {
            // First bind it to itself so we can remount RO without affecting host.
            if (sc.mount(p, p, null, Constants.MS_BIND | Constants.MS_REC, null) != 0) {
                int err = sc.errno();
                if (err == Constants.ENOENT) continue;
                Logger.debug("rebind " + p + ": " + sc.strerror(err));
                continue;
            }
            long flags = Constants.MS_BIND | Constants.MS_REC | Constants.MS_REMOUNT
                    | Constants.MS_RDONLY;
            if (sc.mount(p, p, null, flags, null) != 0) {
                Logger.debug("readonly remount " + p + ": " + sc.strerror(sc.errno()));
            } else {
                Logger.debug("readonly " + p);
            }
        }
    }
}
