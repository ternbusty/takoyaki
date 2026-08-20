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
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
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
            // Do NOT set the rootfs mount to MS_PRIVATE here. The bind mount
            // inherits MS_SLAVE propagation from "/", and that satisfies
            // pivot_root's requirement (new root must not be MS_SHARED).
            // Setting MS_PRIVATE would sever the peer group, making
            // rootfsPropagation "slave" impossible after pivot_root because
            // there would be no peer to slave to.

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
                applyOciMounts(rootfsPath, spec.mounts, idmapFds, spec);
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
                Constants.MS_NOSUID | Constants.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=5") != 0) {
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
        // Check if the spec's cgroup mount should be read-only. By default
        // it is ro, but set_cgroup_mount_writable removes "ro".
        boolean cgroupRo = true;
        if (spec != null && spec.mounts != null) {
            for (Spec.Mount m : spec.mounts) {
                if ("cgroup".equals(m.type) || "/sys/fs/cgroup".equals(m.destination)) {
                    if (m.options != null && !m.options.contains("ro")) {
                        cgroupRo = false;
                    }
                    break;
                }
            }
        }
        // When the spec creates a cgroup namespace, bind-mount only the
        // container's cgroup subtree so the namespace root matches. When
        // there is no cgroup namespace (the spec removes it or joins an
        // existing one via .path), the container must see the full host
        // cgroup tree, so bind-mount the cgroup root instead.
        boolean hasCgroupNs = spec != null && spec.hasNamespace("cgroup");
        if (hasCgroupNs && containerCgPath != null) {
            mountCgroupBind(arena, cg, containerCgPath, cgroupRo);
        } else {
            mountCgroupRoot(arena, cg, cgroupRo);
        }
    }

    /**
     * Mount the full host cgroup tree at the container's /sys/fs/cgroup.
     * Used when no cgroup namespace is configured so the container can see
     * all cgroups on the host (matching runc behaviour).
     */
    private static void mountCgroupRoot(Arena arena, String cg, boolean cgroupRo) {
        if (Libc.mount(arena, "/sys/fs/cgroup", cg, null,
                Constants.MS_BIND | Constants.MS_REC, null) == 0) {
            long remountFlags = Constants.MS_BIND | Constants.MS_REMOUNT
                    | Constants.MS_NOSUID | Constants.MS_NODEV | Constants.MS_NOEXEC;
            if (cgroupRo) remountFlags |= Constants.MS_RDONLY;
            Libc.mount(arena, null, cg, null, remountFlags, null);
            Logger.debug("bound /sys/fs/cgroup from host root"
                    + (cgroupRo ? " (ro)" : " (rw)"));
        } else {
            Logger.warn("bind /sys/fs/cgroup from host root: "
                    + Libc.strerror(Libc.errno()));
        }
    }

    private static void mountCgroupBind(Arena arena, String cg,
                                          String containerCgPath, boolean cgroupRo) {
        if (containerCgPath == null) return;
        String src = "/sys/fs/cgroup" + containerCgPath;
        if (PosixIO.access(arena, src, Constants.F_OK) == 0) {
            if (Libc.mount(arena, src, cg, null,
                    Constants.MS_BIND | Constants.MS_REC, null) == 0) {
                long remountFlags = Constants.MS_BIND | Constants.MS_REMOUNT
                        | Constants.MS_NOSUID | Constants.MS_NODEV | Constants.MS_NOEXEC;
                if (cgroupRo) remountFlags |= Constants.MS_RDONLY;
                Libc.mount(arena, null, cg, null, remountFlags, null);
                Logger.debug("bound /sys/fs/cgroup from " + src
                        + (cgroupRo ? " (ro)" : " (rw)"));
            } else {
                Logger.warn("bind /sys/fs/cgroup from " + src + ": "
                        + Libc.strerror(Libc.errno()));
            }
        } else {
            Logger.debug("cgroup source " + src + " does not exist (yet)");
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
                               java.util.Map<String, Integer> idmapFds,
                               Spec spec) {
        Syscalls sc = SyscallHost.current();
        for (Spec.Mount m : mounts) {
            if (m.destination == null) continue;
            // Strip rootfs prefix from destination if present.  The OCI spec
            // says destination is a container-absolute path ("/mnt/x"), but
            // some callers (e.g. runc integration tests) pass host-absolute
            // paths like "$rootfs/mnt/x" where $rootfs is the host rootfs
            // directory.  This matches runc's LexicallyStripRoot behaviour.
            String dest = m.destination;
            if (dest.startsWith(rootfsPath + "/")) {
                dest = dest.substring(rootfsPath.length());
            } else if (dest.equals(rootfsPath)) {
                dest = "/";
            }
            // skip already-handled paths
            if (dest.equals("/proc") || dest.equals("/dev")
                || dest.equals("/sys") || dest.equals("/dev/shm")
                || dest.equals("/dev/pts") || dest.equals("/dev/mqueue")
                || dest.equals("/sys/fs/cgroup")) continue;
            // Resolve symlinks in the destination path within the rootfs
            // scope, so bind mounts through dangling symlinks end up at the
            // correct host-side path. The resolved target is used for both
            // mkdir and mount(2); the original destination stays for logging.
            String resolved = resolveInRootfs(rootfsPath, dest);
            String target = resolved;
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
            boolean targetExisted = Files.isDirectory(Path.of(target));
            createMountTarget(rootfsPath, m, target, isBind);

            // Id-mapped mounts: if uidMappings/gidMappings are present (or the
            // "idmap"/"ridmap" option is set) we route the bind through
            // open_tree + mount_setattr(MOUNT_ATTR_IDMAP) + move_mount.
            // When "idmap"/"ridmap" is in the options but no mount-level mappings
            // are provided, the container's userns mappings are used (implied).
            // Prefer the host-prepared fd that CreateCommand stashed in idmapFds.
            boolean hasExplicitMappings = m.uidMappings != null && !m.uidMappings.isEmpty();
            boolean wantIdmap = hasExplicitMappings || parsed.isIdmap || parsed.isRecursiveIdmap;
            if (wantIdmap && isBind) {
                boolean recursive = parsed.isRecursiveIdmap;
                // When the bind is recursive (rbind / MS_REC), pass
                // AT_RECURSIVE to open_tree so the clone captures
                // submounts created by earlier entries in this mount
                // loop. Without this, only the top-level mount is
                // cloned and deeply nested paths become invisible.
                boolean cloneRecursive =
                        (flags & Constants.MS_REC) != 0;
                // For implied mapping, synthesize a mount with the container's
                // userns mappings so IdmapHelper can create the right userns.
                Spec.Mount effectiveMount = m;
                if (!hasExplicitMappings && (parsed.isIdmap || parsed.isRecursiveIdmap)) {
                    effectiveMount = new Spec.Mount();
                    effectiveMount.source = m.source;
                    effectiveMount.destination = m.destination;
                    effectiveMount.type = m.type;
                    effectiveMount.options = m.options;
                    if (spec.linux != null) {
                        effectiveMount.uidMappings = spec.linux.uidMappings;
                        effectiveMount.gidMappings = spec.linux.gidMappings;
                    }
                }
                Integer prepFd = idmapFds.get(m.destination);
                boolean done;
                if (prepFd != null) {
                    // The host-side CreateCommand already did open_tree +
                    // mount_setattr(MOUNT_ATTR_IDMAP), so prepFd is a
                    // ready-to-install tree fd. Just move_mount it.
                    done = IdmapMount.moveMount(prepFd, target);
                    PosixIO.close(prepFd);
                    if (done) Logger.debug("idmap mounted " + m.destination
                            + " using host-prepared tree fd " + prepFd);
                } else {
                    done = IdmapHelper.apply(effectiveMount, target,
                            recursive, cloneRecursive);
                    if (done) Logger.debug("idmap mounted " + m.destination
                            + " using in-init helper");
                }
                if (done) {
                    // Apply post-mount operations that a regular bind mount
                    // would get below. The idmap path skips the initial
                    // mount(2) call but the mount still needs propagation,
                    // VFS-flag remounting, and recursive mount attributes.
                    long vfsIdmap = Constants.MS_RDONLY | Constants.MS_NOSUID
                            | Constants.MS_NODEV | Constants.MS_NOEXEC
                            | Constants.MS_NOATIME | Constants.MS_RELATIME
                            | Constants.MS_STRICTATIME | Constants.MS_NOSYMFOLLOW
                            | Constants.MS_NODIRATIME;
                    if ((flags & vfsIdmap) != 0 || parsed.clearedFlags != 0) {
                        long remountFlags = Constants.MS_BIND | Constants.MS_REMOUNT
                                | (flags & vfsIdmap);
                        if (sc.mount(null, target, null, remountFlags, null) != 0) {
                            Logger.debug("bind remount with access flags on "
                                    + m.destination + " (idmap) failed: "
                                    + sc.strerror(sc.errno()));
                        }
                    }
                    if (propagation != 0) {
                        if (sc.mount(null, target, null, propagation, null) != 0) {
                            Logger.debug("propagation set on " + m.destination
                                    + " (idmap) failed: " + sc.strerror(sc.errno()));
                        }
                    }
                    if (parsed.hasRecAttr()) {
                        mountSetattr(target, parsed.recAttrSet, parsed.recAttrClr);
                    }
                    continue;
                }
                Logger.warn("idmap mount failed for " + m.destination + ", falling back to plain bind");
            }

            // runc compat: for tmpfs mounts without an explicit "mode=" option,
            // inherit the permission bits from the existing target directory.
            // This makes "mount tmpfs on /tmp" keep /tmp's chmod'd mode.
            // Only inherit when the target directory existed BEFORE createMountTarget
            // made it; freshly-created directories would just reflect the default
            // mkdir mode (755) which is not the user's intent.
            if ("tmpfs".equals(type) && !isBind && targetExisted) {
                data = inheritTmpfsMode(target, data);
            }

            // tmpcopyup: snapshot directory contents before tmpfs hides them.
            java.util.List<Object[]> tmpcopyupSnapshot = null;
            if (parsed.tmpcopyup && "tmpfs".equals(type) && !isBind
                    && Files.isDirectory(Path.of(target))) {
                tmpcopyupSnapshot = snapshotDirectory(Path.of(target));
            }

            // Container bind-mount source: when the source path does not
            // exist on the host but DOES exist under the rootfs, it refers
            // to a location created by an earlier mount in the same spec
            // (e.g. a tmpfs or another bind). Resolve it rootfs-relative
            // so the mount sees the right content.  This matches runc.
            String mountSource = m.source;
            if (isBind && mountSource != null
                    && !new java.io.File(mountSource).exists()
                    && new java.io.File(rootfsPath + mountSource).exists()) {
                mountSource = rootfsPath + mountSource;
                Logger.debug("resolved container bind source " + m.source
                        + " -> " + mountSource);
            }
            int rc = sc.mount(mountSource, target, isBind ? null : type, flags, data);
            if (rc != 0) {
                Logger.debug("optional mount " + m.destination + " failed: "
                        + sc.strerror(sc.errno()));
                continue;
            }
            Logger.debug("mounted " + m.destination + " (type=" + type + ")");

            // tmpcopyup: restore pre-existing contents into the fresh tmpfs.
            if (tmpcopyupSnapshot != null && !tmpcopyupSnapshot.isEmpty()) {
                restoreDirectory(Path.of(target), tmpcopyupSnapshot);
                Logger.debug("tmpcopyup restored contents into " + m.destination);
            }
            // bind mounts ignore MS_RDONLY (and other access flags) on the initial
            // mount; the kernel just bind-attaches the source as-is. A second
            // MS_BIND|MS_REMOUNT with the desired flags is required to actually
            // enforce them. This also handles "clearing" flags: e.g. "bind,dev"
            // means clear MS_NODEV by not including it in the remount.
            long vfsFlags = Constants.MS_RDONLY | Constants.MS_NOSUID
                    | Constants.MS_NODEV | Constants.MS_NOEXEC
                    | Constants.MS_NOATIME | Constants.MS_RELATIME
                    | Constants.MS_STRICTATIME | Constants.MS_NOSYMFOLLOW
                    | Constants.MS_NODIRATIME;
            if (isBind && ((flags & vfsFlags) != 0 || parsed.clearedFlags != 0)) {
                long remountFlags = Constants.MS_BIND | Constants.MS_REMOUNT
                        | (flags & vfsFlags);
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
            // Recursive mount attributes (rro, rnoatime, etc.) require the
            // mount_setattr(2) syscall with AT_RECURSIVE, applied after the
            // regular mount(2). This makes the attribute change propagate to
            // all submounts recursively.
            if (parsed.hasRecAttr()) {
                mountSetattr(target, parsed.recAttrSet, parsed.recAttrClr);
            }
        }
    }

    public static void pivot(String newRoot, String rootfsPropagation) {
        try (Arena arena = Arena.ofConfined()) {
            Logger.debug("pivot_root to " + newRoot);
            // Open "/" BEFORE pivot so we have an fd to the old root.
            // After pivot_root, this fd still references the old root mount.
            int oldrootFd = PosixIO.open(arena, "/",
                    Constants.O_DIRECTORY | Constants.O_RDONLY, 0);
            if (oldrootFd < 0) {
                throw new RuntimeException("open /: " + Libc.strerror(Libc.errno()));
            }
            // Also open the new root to fchdir into it for pivot_root(".", ".").
            int newrootFd = PosixIO.open(arena, newRoot,
                    Constants.O_DIRECTORY | Constants.O_RDONLY, 0);
            if (newrootFd < 0) {
                PosixIO.close(oldrootFd);
                throw new RuntimeException("open " + newRoot + ": " + Libc.strerror(Libc.errno()));
            }
            try {
                // fchdir to new root so pivot_root(".", ".") acts on it.
                if (PosixIO.fchdir(newrootFd) != 0) {
                    throw new RuntimeException("fchdir newroot: " + Libc.strerror(Libc.errno()));
                }
                if (Libc.pivotRoot(arena, ".", ".") != 0) {
                    throw new RuntimeException("pivot_root: " + Libc.strerror(Libc.errno()));
                }
                // After pivot_root(".", "."), cwd is the old root (kernel
                // behavior). fchdir to the old root fd to be safe, then make
                // the old root (and all its children) MS_SLAVE recursively
                // so our unmount doesn't propagate to the host. This targets
                // the OLD root only, preserving propagation flags on mounts
                // under the NEW root (e.g. MS_SHARED on idmap mounts).
                if (PosixIO.fchdir(oldrootFd) != 0) {
                    throw new RuntimeException("fchdir oldroot: " + Libc.strerror(Libc.errno()));
                }
                if (Libc.mount(arena, null, ".", null,
                        Constants.MS_SLAVE | Constants.MS_REC, null) != 0) {
                    Logger.warn("remount oldroot as slave failed: " + Libc.strerror(Libc.errno()));
                }
                if (Libc.umount2(arena, ".", Constants.MNT_DETACH) != 0) {
                    Logger.warn("umount2 oldroot failed: " + Libc.strerror(Libc.errno()));
                }
            } finally {
                PosixIO.close(newrootFd);
                PosixIO.close(oldrootFd);
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
                    // runc compat: rootfsPropagation is always applied
                    // recursively, regardless of whether the config value
                    // uses the "r" prefix or not.
                    prop |= Constants.MS_REC;
                    // The kernel's MS_SHARED does NOT clear an existing slave
                    // relationship, resulting in shared+slave instead of pure
                    // shared. Clear any slave state with MS_PRIVATE first so
                    // the final propagation is exactly what the spec requests.
                    // Only needed for MS_SHARED; the kernel's MS_PRIVATE and
                    // MS_SLAVE already handle existing relationships correctly.
                    if ((prop & Constants.MS_SHARED) != 0) {
                        Libc.mount(arena, null, "/", null,
                                Constants.MS_PRIVATE | Constants.MS_REC, null);
                    }
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

    /**
     * Alternative to {@link #pivot} when {@code --no-pivot} is requested.
     * Moves the rootfs mount to "/" via {@code mount(MS_MOVE)} and then
     * calls {@code chroot(".")} + {@code chdir("/")}. This is the same
     * approach runc uses in its {@code msMoveRoot} function.
     *
     * Unlike pivot_root, this does NOT detach the old root. The old root's
     * mounts remain in the mount namespace (but are inaccessible from
     * userspace because they're hidden under the new root).
     */
    public static void msMoveRoot(String newRoot, String rootfsPropagation) {
        try (Arena arena = Arena.ofConfined()) {
            Logger.debug("msMoveRoot (no-pivot) to " + newRoot);

            // Before MS_MOVE, mask host procfs and sysfs mounts.  runc
            // lazy-unmounts them so the container cannot re-mount procfs
            // writable (which would expose bare /proc).  Collect targets
            // first because /proc/self/mountinfo disappears after unmount.
            java.util.List<String> toUnmount = new java.util.ArrayList<>();
            try {
                for (String line : Files.readAllLines(Path.of("/proc/self/mountinfo"))) {
                    String[] parts = line.split(" ");
                    if (parts.length < 9) continue;
                    String root = parts[3];
                    String mountPoint = parts[4];
                    int dashIdx = -1;
                    for (int i = 6; i < parts.length; i++) {
                        if ("-".equals(parts[i])) { dashIdx = i; break; }
                    }
                    if (dashIdx < 0 || dashIdx + 1 >= parts.length) continue;
                    String fstype = parts[dashIdx + 1];
                    if (!"/".equals(root)) continue;
                    if (!"proc".equals(fstype) && !"sysfs".equals(fstype)) continue;
                    if (mountPoint.startsWith(newRoot)) continue;
                    toUnmount.add(mountPoint);
                }
            } catch (IOException e) {
                Logger.warn("msMoveRoot: failed to read mountinfo: " + e.getMessage());
            }
            for (String mp : toUnmount) {
                Libc.mount(arena, null, mp, null,
                        Constants.MS_SLAVE | Constants.MS_REC, null);
                if (Libc.umount2(arena, mp, Constants.MNT_DETACH) != 0) {
                    Libc.mount(arena, "tmpfs", mp, "tmpfs", 0, null);
                    Logger.debug("covered " + mp + " with tmpfs");
                } else {
                    Logger.debug("lazy-unmounted host mount at " + mp);
                }
            }

            // Grab an fd to the rootfs BEFORE MS_MOVE. After the move, the
            // process cwd/root still reference the ORIGINAL root mount (now
            // covered by the rootfs mount). Path-based chdir("/") would stay
            // on the original root because "/" resolves to the process root
            // without mount traversal. Using fchdir(fd) sidesteps this: the
            // fd follows the mount wherever it goes.
            int rootFd = PosixIO.open(arena, newRoot,
                    Constants.O_DIRECTORY | Constants.O_RDONLY, 0);
            if (rootFd < 0) {
                throw new RuntimeException("open " + newRoot + ": "
                        + Libc.strerror(Libc.errno()));
            }

            if (Libc.mount(arena, newRoot, "/", null, Constants.MS_MOVE, null) != 0) {
                PosixIO.close(rootFd);
                throw new RuntimeException("mount MS_MOVE " + newRoot + " to /: "
                        + Libc.strerror(Libc.errno()));
            }

            // fchdir to the rootfs mount (fd follows the MS_MOVE), then
            // chroot(".") to lock the root. Finally chdir("/") for sanity.
            if (PosixIO.fchdir(rootFd) != 0) {
                PosixIO.close(rootFd);
                throw new RuntimeException("fchdir: " + Libc.strerror(Libc.errno()));
            }
            PosixIO.close(rootFd);
            if (Libc.chroot(arena, ".") != 0) {
                throw new RuntimeException("chroot: " + Libc.strerror(Libc.errno()));
            }
            if (Libc.chdir(arena, "/") != 0) {
                throw new RuntimeException("chdir /: " + Libc.strerror(Libc.errno()));
            }
            // Apply rootfsPropagation the same way as pivot().
            if (rootfsPropagation != null) {
                long prop = MountOptions.propagationFlag(rootfsPropagation);
                if (prop != 0) {
                    prop |= Constants.MS_REC;
                    if ((prop & Constants.MS_SHARED) != 0) {
                        Libc.mount(arena, null, "/", null,
                                Constants.MS_PRIVATE | Constants.MS_REC, null);
                    }
                    if (Libc.mount(arena, null, "/", null, prop, null) != 0) {
                        Logger.warn("set / to " + rootfsPropagation + " failed: "
                                + Libc.strerror(Libc.errno()));
                    } else {
                        Logger.debug("/ propagation set to " + rootfsPropagation);
                    }
                }
            }
            Logger.debug("msMoveRoot completed");
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
    /**
     * Create the mount target directory or file at the already-resolved host
     * path {@code target}. For bind mounts where the source is a regular file,
     * create a file (not a directory).
     */
    private static void createMountTarget(String rootfsPath, Spec.Mount m,
                                          String target, boolean isBind) {
        try {
            boolean isFile = false;
            if (isBind && m.source != null) {
                Path srcPath = Path.of(m.source);
                if (!srcPath.isAbsolute()) {
                    srcPath = Path.of(System.getProperty("user.dir", ".")).resolve(srcPath);
                }
                if (Files.isRegularFile(srcPath)) {
                    isFile = true;
                }
            }
            Path targetPath = Path.of(target);
            if (isFile) {
                Files.createDirectories(targetPath.getParent());
                if (!Files.exists(targetPath)) {
                    Files.createFile(targetPath);
                }
            } else {
                Files.createDirectories(targetPath);
            }
        } catch (IOException e) {
            try { Files.createDirectories(Path.of(target)); }
            catch (IOException ignored) {}
        }
    }

    /**
     * Resolve a container-relative path within rootfsPath, following symlinks
     * component by component but keeping the result under rootfsPath.
     * Returns the fully resolved host-side path.
     *
     * <p>When a symlink target is itself an absolute path (e.g. /tmp/foo), it
     * is re-rooted under rootfsPath. Its components are then resolved
     * recursively so multi-hop chains (A -> /B -> /C/D) work.
     */
    private static String resolveInRootfs(String rootfsPath, String destination) {
        Path rootfs = Path.of(rootfsPath);
        return resolveComponents(rootfs, destination.split("/"), 0, rootfs, 0).toString();
    }

    private static Path resolveComponents(Path rootfs, String[] components,
                                           int startIdx, Path current, int depth) {
        if (depth > 255) return current; // symlink loop guard
        for (int i = startIdx; i < components.length; i++) {
            String comp = components[i];
            if (comp.isEmpty()) continue;
            Path next = current.resolve(comp);
            if (Files.isSymbolicLink(next)) {
                try {
                    Path linkTarget = Files.readSymbolicLink(next);
                    Path base;
                    if (linkTarget.isAbsolute()) {
                        base = rootfs;
                    } else {
                        base = current;
                    }
                    // Resolve the symlink target's components recursively so
                    // multi-hop chains are followed correctly.
                    String linkStr = linkTarget.toString();
                    if (linkTarget.isAbsolute()) linkStr = linkStr.substring(1);
                    String[] linkParts = linkStr.split("/");
                    // Concatenate remaining original components after the link parts.
                    int remaining = components.length - i - 1;
                    String[] merged = new String[linkParts.length + remaining];
                    System.arraycopy(linkParts, 0, merged, 0, linkParts.length);
                    System.arraycopy(components, i + 1, merged, linkParts.length, remaining);
                    Path resolved = resolveComponents(rootfs, merged, 0, base, depth + 1);
                    // Security: ensure we're still under rootfs.
                    if (!resolved.normalize().startsWith(rootfs)) return rootfs;
                    return resolved;
                } catch (IOException e) {
                    current = next;
                }
            } else {
                current = next;
            }
        }
        return current;
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

    /**
     * Snapshot a directory tree into a list of entries, each represented as
     * {@code {type, relativePath, payload, mode}}. Types are "dir", "file",
     * or "symlink". Payload is {@code byte[]} for files, a symlink-target
     * string for symlinks, and null for directories. Mode is the Unix
     * permission bits (int), preserved so tmpcopyup restores chmod'd modes.
     */
    private static java.util.List<Object[]> snapshotDirectory(Path dir) {
        java.util.List<Object[]> entries = new java.util.ArrayList<>();
        if (!Files.isDirectory(dir)) return entries;
        try (java.util.stream.Stream<Path> walk = Files.walk(dir)) {
            walk.forEach(p -> {
                if (p.equals(dir)) return;
                String rel = dir.relativize(p).toString();
                try {
                    int mode = -1;
                    try {
                        mode = ((int) Files.getAttribute(p, "unix:mode",
                                java.nio.file.LinkOption.NOFOLLOW_LINKS)) & 07777;
                    } catch (Exception ignored) {}
                    if (Files.isSymbolicLink(p)) {
                        entries.add(new Object[]{
                                "symlink", rel, Files.readSymbolicLink(p).toString(), mode});
                    } else if (Files.isDirectory(p)) {
                        entries.add(new Object[]{"dir", rel, null, mode});
                    } else if (Files.isRegularFile(p)) {
                        entries.add(new Object[]{
                                "file", rel, Files.readAllBytes(p), mode});
                    }
                } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
        return entries;
    }

    /**
     * Restore a snapshot produced by {@link #snapshotDirectory} into the
     * given target directory (typically a freshly-mounted tmpfs), preserving
     * Unix permission bits.
     */
    private static void restoreDirectory(Path dir, java.util.List<Object[]> entries) {
        for (Object[] e : entries) {
            String type = (String) e[0];
            Path target = dir.resolve((String) e[1]);
            int mode = (int) e[3];
            try {
                switch (type) {
                    case "dir":
                        Files.createDirectories(target);
                        if (mode >= 0) {
                            Files.setPosixFilePermissions(target,
                                    java.nio.file.attribute.PosixFilePermissions.fromString(
                                            modeToPerms(mode)));
                        }
                        break;
                    case "file":
                        Files.createDirectories(target.getParent());
                        Files.write(target, (byte[]) e[2]);
                        if (mode >= 0) {
                            Files.setPosixFilePermissions(target,
                                    java.nio.file.attribute.PosixFilePermissions.fromString(
                                            modeToPerms(mode)));
                        }
                        break;
                    case "symlink":
                        Files.createDirectories(target.getParent());
                        if (!Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                            Files.createSymbolicLink(target, Path.of((String) e[2]));
                        }
                        break;
                }
            } catch (IOException ex) {
                Logger.debug("tmpcopyup restore " + e[1] + ": " + ex.getMessage());
            }
        }
    }

    /** Convert a Unix permission mode (0777, etc.) to a PosixFilePermissions string. */
    private static String modeToPerms(int mode) {
        char[] p = new char[9];
        p[0] = (mode & 0400) != 0 ? 'r' : '-';
        p[1] = (mode & 0200) != 0 ? 'w' : '-';
        p[2] = (mode & 0100) != 0 ? 'x' : '-';
        p[3] = (mode & 040) != 0 ? 'r' : '-';
        p[4] = (mode & 020) != 0 ? 'w' : '-';
        p[5] = (mode & 010) != 0 ? 'x' : '-';
        p[6] = (mode & 04) != 0 ? 'r' : '-';
        p[7] = (mode & 02) != 0 ? 'w' : '-';
        p[8] = (mode & 01) != 0 ? 'x' : '-';
        return new String(p);
    }

    /**
     * Call mount_setattr(2) with AT_RECURSIVE on the given path.
     *
     * struct mount_attr (size = MOUNT_ATTR_SIZE_VER0 = 32 bytes)
     *   u64 attr_set      (offset  0)
     *   u64 attr_clr      (offset  8)
     *   u64 propagation   (offset 16)
     *   u64 userns_fd     (offset 24)
     *
     * runc pattern (rootfs_linux.go setRecAttr): opens the target via
     * /proc/self/fd to avoid TOCTOU, then calls mount_setattr(-1, procfd,
     * AT_RECURSIVE, &attr). We simplify by passing the path directly since
     * we are in a private mount namespace and there is no TOCTOU window.
     */
    private static void mountSetattr(String target, long attrSet, long attrClr) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment attr = arena.allocate(32);
            attr.set(ValueLayout.JAVA_LONG, 0, attrSet);
            attr.set(ValueLayout.JAVA_LONG, 8, attrClr);
            attr.set(ValueLayout.JAVA_LONG, 16, 0L); // propagation
            attr.set(ValueLayout.JAVA_LONG, 24, 0L); // userns_fd
            MemorySegment path = arena.allocateFrom(target);
            long rc = Libc.syscall(Constants.NR_mount_setattr,
                    -1, path.address(), Constants.AT_RECURSIVE, attr.address(), 32);
            if (rc != 0) {
                Logger.debug("mount_setattr(AT_RECURSIVE) on " + target + " failed: "
                        + Libc.strerror(Libc.errno()));
            } else {
                Logger.debug("mount_setattr(AT_RECURSIVE) applied on " + target
                        + " set=0x" + Long.toHexString(attrSet)
                        + " clr=0x" + Long.toHexString(attrClr));
            }
        }
    }
}
