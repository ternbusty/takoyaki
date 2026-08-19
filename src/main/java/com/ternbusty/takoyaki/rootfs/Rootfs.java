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
            // runc compat: pass the spec's /dev mount options (if any) so that
            // "ro" in the spec actually makes /dev read-only.
            long devExtraFlags = 0;
            if (spec.mounts != null) {
                for (Spec.Mount sm : spec.mounts) {
                    if ("/dev".equals(sm.destination)) {
                        MountOptions.Parsed dp = MountOptions.parse(sm.options);
                        devExtraFlags = dp.flags;
                        break;
                    }
                }
            }
            mountDev(arena, rootfsPath, devExtraFlags);
            mountSys(arena, rootfsPath, spec);

            if (spec.mounts != null) {
                applyOciMounts(rootfsPath, spec.mounts, idmapFds);
            }
        }
    }

    private static void mountProc(Arena arena, String rootfsPath) {
        String p = rootfsPath + "/proc";
        // runc compat: /proc must be a real directory, not a symlink.
        if (Files.isSymbolicLink(Path.of(p))) {
            throw new RuntimeException("/proc must be mounted on ordinary directory");
        }
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

    private static void mountDev(Arena arena, String rootfsPath, long extraFlags) {
        String dev = rootfsPath + "/dev";
        if (PosixIO.access(arena, dev, Constants.F_OK) != 0) {
            try { Files.createDirectories(Path.of(dev)); }
            catch (IOException e) { Logger.warn("mkdir dev: " + e.getMessage()); return; }
        }
        long devFlags = Constants.MS_NOSUID | Constants.MS_NOEXEC | extraFlags;
        if (Libc.mount(arena, "tmpfs", dev, "tmpfs",
                devFlags, "mode=755") != 0) {
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
        String[][] symlinks = {
                {"ptmx",   "pts/ptmx"},
                {"fd",     "/proc/self/fd"},
                {"stdin",  "/proc/self/fd/0"},
                {"stdout", "/proc/self/fd/1"},
                {"stderr", "/proc/self/fd/2"},
        };
        try {
            Path devPath = Path.of(dev);
            for (String[] link : symlinks) {
                Path p = devPath.resolve(link[0]);
                if (!Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    Files.createSymbolicLink(p, Path.of(link[1]));
                }
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
        // runc compat: /sys must be a real directory, not a symlink.
        if (Files.isSymbolicLink(Path.of(sys))) {
            throw new RuntimeException("/sys must be mounted on ordinary directory");
        }
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

    /**
     * Apply spec.mounts in order. Package-visible so the unit test can drive
     * this directly against a RecordingSyscalls fake — the previous private
     * signature meant this loop was only reachable via the full Rootfs.prepare
     * path which can't be unit-tested.
     */
    static void applyOciMounts(String rootfsPath, List<Spec.Mount> mounts,
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
            // Create the target mount point. For bind mounts where the source
            // is a regular file, create a file (not a directory). runc follows
            // symlinks in the destination path within the rootfs and creates
            // intermediate directories as needed.
            createMountTarget(rootfsPath, m, target, isBind);

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

            // runc compat: for tmpfs mounts without an explicit "mode=" option,
            // inherit the permission bits from the existing target directory.
            // This makes "mount tmpfs on /tmp" keep /tmp's chmod'd mode.
            if ("tmpfs".equals(type) && !isBind) {
                data = inheritTmpfsMode(target, data);
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
                // runc compat: after pivot_root(new, new), the old root is
                // stacked on top of the new root. We need to make the old root
                // (and all mounts under it) slaves before detaching. Using "."
                // targets the old root mount rather than the new root underneath.
                if (PosixIO.fchdir(newrootFd) != 0) {
                    throw new RuntimeException("fchdir: " + Libc.strerror(Libc.errno()));
                }
                if (Libc.mount(arena, null, ".", null,
                        Constants.MS_SLAVE | Constants.MS_REC, null) != 0) {
                    Logger.warn("remount . as slave failed: " + Libc.strerror(Libc.errno()));
                }
                if (Libc.umount2(arena, ".", Constants.MNT_DETACH) != 0) {
                    Logger.warn("umount2 . failed: " + Libc.strerror(Libc.errno()));
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
                long prop = MountOptions.propagationFlag(rootfsPropagation);
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
        // runc compat: deduplicate paths so each is masked exactly once.
        java.util.LinkedHashSet<String> deduped = new java.util.LinkedHashSet<>(paths);
        // runc mounts a single tmpfs for all directory masks and bind-mounts
        // it onto each target, so all share the same device number.
        String tmpfsSource = null;
        for (String p : deduped) {
            int rc = sc.mount("/dev/null", p, null, Constants.MS_BIND, null);
            if (rc == 0) {
                Logger.debug("masked " + p + " with /dev/null");
                continue;
            }
            int err = sc.errno();
            if (err == Constants.ENOENT) continue; // skip nonexistent
            // Likely a directory. Mount a single shared tmpfs on the first
            // directory, then bind-mount it onto subsequent directories so
            // all directory masks share the same device number (runc compat).
            if (tmpfsSource == null) {
                rc = sc.mount("tmpfs", p, "tmpfs", Constants.MS_RDONLY, null);
                if (rc != 0) {
                    Logger.debug("mask " + p + " failed: " + sc.strerror(sc.errno()));
                } else {
                    tmpfsSource = p;
                    Logger.debug("masked " + p + " with tmpfs");
                }
            } else {
                rc = sc.mount(tmpfsSource, p, null,
                        Constants.MS_BIND | Constants.MS_RDONLY, null);
                if (rc != 0) {
                    Logger.debug("mask bind " + p + " failed: " + sc.strerror(sc.errno()));
                } else {
                    Logger.debug("masked " + p + " via bind from " + tmpfsSource);
                }
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

    /**
     * Create the target mount point for an OCI mount. For bind mounts where the
     * source is a regular file (not a directory), create a file; otherwise
     * create a directory. Also resolves symlinks in the destination path within
     * the rootfs scope, creating intermediate directories as needed.
     */
    private static void createMountTarget(String rootfsPath, Spec.Mount m,
                                          String target, boolean isBind) {
        try {
            // Resolve the full target path within rootfs, following symlinks.
            String resolved = resolveInRootfs(rootfsPath, m.destination);
            boolean isFile = false;
            if (isBind && m.source != null) {
                // Check if the source is a file (not a directory).
                Path srcPath = Path.of(m.source);
                if (!srcPath.isAbsolute()) {
                    // Relative source: resolve against CWD (spec bundle dir).
                    srcPath = Path.of(System.getProperty("user.dir", ".")).resolve(srcPath);
                }
                if (Files.isRegularFile(srcPath)) {
                    isFile = true;
                }
            }
            if (isFile) {
                // Create parent directories then touch the target file.
                Path resolvedPath = Path.of(resolved);
                Files.createDirectories(resolvedPath.getParent());
                if (!Files.exists(resolvedPath)) {
                    Files.createFile(resolvedPath);
                }
            } else {
                Files.createDirectories(Path.of(resolved));
            }
        } catch (IOException e) {
            // Fallback: use the literal target path.
            try { Files.createDirectories(Path.of(target)); }
            catch (IOException ignored) {}
        }
    }

    /**
     * Resolve a container-relative path within rootfsPath, following symlinks
     * component by component but keeping the result under rootfsPath.
     * Returns the fully resolved host-side path.
     */
    private static String resolveInRootfs(String rootfsPath, String destination) {
        Path rootfs = Path.of(rootfsPath);
        // Split destination into components and resolve one at a time.
        String[] components = destination.split("/");
        Path current = rootfs;
        for (String comp : components) {
            if (comp.isEmpty()) continue;
            Path next = current.resolve(comp);
            if (Files.isSymbolicLink(next)) {
                try {
                    Path linkTarget = Files.readSymbolicLink(next);
                    if (linkTarget.isAbsolute()) {
                        // Absolute symlink: re-root under rootfs.
                        current = rootfs.resolve(linkTarget.toString().substring(1)).normalize();
                    } else {
                        current = current.resolve(linkTarget).normalize();
                    }
                    // Security: ensure we're still under rootfs.
                    if (!current.startsWith(rootfs)) {
                        current = rootfs;
                    }
                } catch (IOException e) {
                    current = next;
                }
            } else {
                current = next;
            }
        }
        return current.toString();
    }

    /**
     * runc compat: for tmpfs mounts, if no explicit "mode=" is in the data
     * string, read the existing target directory's permission bits and inject
     * "mode=<octal>" so the tmpfs inherits them. Without this, tmpfs defaults
     * to mode 1777, losing any chmod the user applied to the directory before
     * mounting.
     */
    private static String inheritTmpfsMode(String target, String data) {
        if (data != null && data.contains("mode=")) return data;
        try {
            int unixMode = (int) Files.getAttribute(Path.of(target), "unix:mode",
                    java.nio.file.LinkOption.NOFOLLOW_LINKS);
            int mode = unixMode & 07777;
            String modeStr = "mode=0" + Integer.toOctalString(mode);
            Logger.debug("tmpfs inheriting " + modeStr + " from " + target);
            if (data == null || data.isEmpty()) return modeStr;
            return data + "," + modeStr;
        } catch (Exception e) {
            Logger.debug("could not read target mode for tmpfs: " + e.getMessage());
            return data;
        }
    }
}
