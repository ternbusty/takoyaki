package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.syscall.SyscallHost
import java.io.File
import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions

object Rootfs {

    // Default /dev entries that get bind-mounted from the host at container
    // start-up. Matches the set every OCI runtime provides by default -- the
    // audit against runc / youki flagged /dev/console as missing here.
    // /dev/console is typically 0600 root:root on the host, so the bind
    // silently no-ops in rootless mode (bindDevice logs and moves on).
    private val DEVICES = arrayOf("null", "zero", "random", "urandom", "tty", "full", "console")

    fun prepare(
        rootfsPath: String,
        spec: Spec,
        idmapFds: Map<String, Int>,
        idmapUsernsFds: Map<String, IntArray>,
        bindSourceFds: Map<String, Int>,
    ) {
        Arena.ofConfined().use { arena ->
            if (PosixIO.access(arena, rootfsPath, Constants.F_OK) != 0) {
                throw RuntimeException("rootfs not found: $rootfsPath")
            }

            // Always set / to slave|rec BEFORE pivot_root. pivot_root requires the
            // new root (and its parent) not to be MS_SHARED. spec.linux.rootfsPropagation
            // is applied AFTER pivot_root, see pivot().
            Logger.debug("set / propagation to slave")
            if (Libc.mount(arena, null, "/", null,
                    Constants.MS_SLAVE or Constants.MS_REC, null) != 0) {
                Logger.warn("mount / MS_SLAVE failed: ${Libc.strerror(Libc.errno())}")
            }

            // Always bind-mount the rootfs to itself so it becomes its own mount,
            // which pivot_root requires. For overlay rootfs (containerd) this is also
            // important to detach the mount from the host's shared propagation.
            Logger.debug("bind mount rootfs: $rootfsPath")
            if (Libc.mount(arena, rootfsPath, rootfsPath, null,
                    Constants.MS_BIND or Constants.MS_REC, null) != 0) {
                throw RuntimeException("bind mount rootfs failed: ${Libc.strerror(Libc.errno())}")
            }
            // Do NOT set the rootfs mount to MS_PRIVATE here. The bind mount
            // inherits MS_SLAVE propagation from "/", and that satisfies
            // pivot_root's requirement (new root must not be MS_SHARED).
            // Setting MS_PRIVATE would sever the peer group, making
            // rootfsPropagation "slave" impossible after pivot_root because
            // there would be no peer to slave to.

            mountProc(arena, rootfsPath)
            // runc compat: pass the spec's /dev mount options (if any) so that
            // "ro" in the spec actually makes /dev read-only.
            var devExtraFlags = 0L
            val specMounts = spec.mounts
            if (specMounts != null) {
                for (sm in specMounts) {
                    if ("/dev" == sm.destination) {
                        val dp = MountOptions.parse(sm.options)
                        devExtraFlags = dp.flags
                        break
                    }
                }
            }
            mountDev(arena, rootfsPath, devExtraFlags)
            mountSys(arena, rootfsPath, spec)

            if (specMounts != null) {
                applyOciMounts(rootfsPath, specMounts, idmapFds, idmapUsernsFds,
                    bindSourceFds, spec)
            }
        }
    }

    private fun mountProc(arena: Arena, rootfsPath: String) {
        val p = "$rootfsPath/proc"
        // runc compat: /proc must be a real directory, not a symlink.
        if (Files.isSymbolicLink(Path.of(p))) {
            throw RuntimeException("/proc must be mounted on ordinary directory")
        }
        if (PosixIO.access(arena, p, Constants.F_OK) != 0) {
            try {
                Files.createDirectories(Path.of(p))
            } catch (e: IOException) {
                Logger.warn("mkdir proc: ${e.message}")
                return
            }
        }
        if (Libc.mount(arena, "proc", p, "proc",
                Constants.MS_NOSUID or Constants.MS_NODEV or Constants.MS_NOEXEC, null) != 0) {
            Logger.warn("mount /proc: ${Libc.strerror(Libc.errno())}")
        } else {
            Logger.debug("mounted /proc")
        }
    }

    private fun mountDev(arena: Arena, rootfsPath: String, extraFlags: Long) {
        val dev = "$rootfsPath/dev"
        if (PosixIO.access(arena, dev, Constants.F_OK) != 0) {
            try {
                Files.createDirectories(Path.of(dev))
            } catch (e: IOException) {
                Logger.warn("mkdir dev: ${e.message}")
                return
            }
        }
        val devFlags = Constants.MS_NOSUID or Constants.MS_NOEXEC or extraFlags
        if (Libc.mount(arena, "tmpfs", dev, "tmpfs", devFlags, "mode=755") != 0) {
            Logger.warn("mount /dev tmpfs: ${Libc.strerror(Libc.errno())}")
            return
        }
        Logger.debug("mounted /dev (tmpfs)")
        for (d in DEVICES) bindDevice(arena, dev, d)

        // OCI default mount order under /dev is pts -> shm -> mqueue; matching it
        // makes runtime-tools' "found in order" check pass since the spec lists
        // them in that order and the test scans /proc/self/mountinfo forward-only.
        val pts = "$dev/pts"
        try { Files.createDirectories(Path.of(pts)) } catch (_: IOException) {}
        if (Libc.mount(arena, "devpts", pts, "devpts",
                Constants.MS_NOSUID or Constants.MS_NOEXEC,
                "newinstance,ptmxmode=0666,mode=0620,gid=5") != 0) {
            Logger.debug("mount /dev/pts: ${Libc.strerror(Libc.errno())}")
        }

        val shm = "$dev/shm"
        try { Files.createDirectories(Path.of(shm)) } catch (_: IOException) {}
        if (Libc.mount(arena, "shm", shm, "tmpfs",
                Constants.MS_NOSUID or Constants.MS_NODEV or Constants.MS_NOEXEC,
                "mode=1777,size=65536k") != 0) {
            Logger.warn("mount /dev/shm: ${Libc.strerror(Libc.errno())}")
        } else {
            Logger.debug("mounted /dev/shm")
        }

        // /dev/mqueue (OCI default mount). Required by runtime-tools default test.
        val mqueue = "$dev/mqueue"
        try { Files.createDirectories(Path.of(mqueue)) } catch (_: IOException) {}
        if (Libc.mount(arena, "mqueue", mqueue, "mqueue",
                Constants.MS_NOSUID or Constants.MS_NODEV or Constants.MS_NOEXEC, null) != 0) {
            Logger.debug("mount /dev/mqueue: ${Libc.strerror(Libc.errno())}")
        } else {
            Logger.debug("mounted /dev/mqueue")
        }

        // OCI default symlinks under /dev that runtime-tools verifies.
        val symlinks = arrayOf(
            arrayOf("ptmx", "pts/ptmx"),
            arrayOf("fd", "/proc/self/fd"),
            arrayOf("stdin", "/proc/self/fd/0"),
            arrayOf("stdout", "/proc/self/fd/1"),
            arrayOf("stderr", "/proc/self/fd/2"),
        )
        try {
            val devPath = Path.of(dev)
            for (link in symlinks) {
                val target = devPath.resolve(link[0])
                if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                    Files.createSymbolicLink(target, Path.of(link[1]))
                }
            }
            Logger.debug("created /dev default symlinks")
        } catch (e: IOException) {
            Logger.debug("dev symlinks: ${e.message}")
        }
    }

    private fun bindDevice(arena: Arena, devPath: String, name: String) {
        val target = "$devPath/$name"
        val fd = PosixIO.open(arena, target, Constants.O_RDWR or Constants.O_CREAT, 0x1b6 /* 0666 */)
        if (fd >= 0) {
            PosixIO.close(fd)
        } else if (Libc.errno() != Constants.EEXIST) {
            Logger.warn("create $target: ${Libc.strerror(Libc.errno())}")
            return
        }
        if (Libc.mount(arena, "/dev/$name", target, null, Constants.MS_BIND, null) != 0) {
            if (Libc.errno() != Constants.EBUSY) {
                Logger.warn("bind /dev/$name: ${Libc.strerror(Libc.errno())}")
            }
        } else {
            Logger.debug("bind mounted /dev/$name")
        }
    }

    private fun mountSys(arena: Arena, rootfsPath: String, spec: Spec?) {
        val sys = "$rootfsPath/sys"
        // runc compat: /sys must be a real directory, not a symlink.
        if (Files.isSymbolicLink(Path.of(sys))) {
            throw RuntimeException("/sys must be mounted on ordinary directory")
        }
        if (PosixIO.access(arena, sys, Constants.F_OK) != 0) {
            try {
                Files.createDirectories(Path.of(sys))
            } catch (e: IOException) {
                Logger.warn("mkdir sys: ${e.message}")
                return
            }
        }
        val flags = Constants.MS_NOSUID or Constants.MS_NODEV or Constants.MS_NOEXEC or Constants.MS_RDONLY
        if (Libc.mount(arena, "sysfs", sys, "sysfs", flags, null) != 0) {
            val e = Libc.errno()
            if (e == Constants.EPERM) {
                Logger.debug("sysfs mount EPERM (user ns?), bind from host /sys")
                if (Libc.mount(arena, "/sys", sys, null,
                        Constants.MS_BIND or Constants.MS_REC, null) != 0) {
                    Logger.warn("bind /sys: ${Libc.strerror(Libc.errno())}")
                }
            } else {
                Logger.warn("mount /sys: ${Libc.strerror(e)}")
            }
        } else {
            Logger.debug("mounted /sys")
        }

        // /sys/fs/cgroup
        val cg = "$sys/fs/cgroup"
        try { Files.createDirectories(Path.of(cg)) } catch (_: IOException) {}
        val specLinux = spec?.linux
        val cgPath = specLinux?.cgroupsPath
        val containerCgPath = if (cgPath != null) {
            if (cgPath.startsWith("/")) cgPath
            else "/$cgPath"
        } else {
            readContainerCgroupPath()
        }
        // Check if the spec's cgroup mount should be read-only. By default
        // it is ro, but set_cgroup_mount_writable removes "ro".
        var cgroupRo = true
        val sysMounts = spec?.mounts
        if (sysMounts != null) {
            for (m in sysMounts) {
                if ("cgroup" == m.type || "/sys/fs/cgroup" == m.destination) {
                    val opts = m.options
                    if (opts != null && "ro" !in opts) {
                        cgroupRo = false
                    }
                    break
                }
            }
        }
        // When the spec creates a cgroup namespace, bind-mount only the
        // container's cgroup subtree so the namespace root matches. When
        // there is no cgroup namespace (the spec removes it or joins an
        // existing one via .path), the container must see the full host
        // cgroup tree, so bind-mount the cgroup root instead.
        val hasCgroupNs = spec != null && spec.hasNamespace("cgroup")
        if (hasCgroupNs && containerCgPath != null) {
            mountCgroupBind(arena, cg, containerCgPath, cgroupRo)
        } else {
            mountCgroupRoot(arena, cg, cgroupRo)
        }
    }

    /**
     * Mount the full host cgroup tree at the container's /sys/fs/cgroup.
     * Used when no cgroup namespace is configured so the container can see
     * all cgroups on the host (matching runc behaviour).
     */
    private fun mountCgroupRoot(arena: Arena, cg: String, cgroupRo: Boolean) {
        if (Libc.mount(arena, "/sys/fs/cgroup", cg, null,
                Constants.MS_BIND or Constants.MS_REC, null) == 0) {
            var remountFlags = Constants.MS_BIND or Constants.MS_REMOUNT or
                Constants.MS_NOSUID or Constants.MS_NODEV or Constants.MS_NOEXEC
            if (cgroupRo) remountFlags = remountFlags or Constants.MS_RDONLY
            Libc.mount(arena, null, cg, null, remountFlags, null)
            Logger.debug("bound /sys/fs/cgroup from host root" +
                if (cgroupRo) " (ro)" else " (rw)")
        } else {
            Logger.warn("bind /sys/fs/cgroup from host root: ${Libc.strerror(Libc.errno())}")
        }
    }

    private fun mountCgroupBind(
        arena: Arena,
        cg: String,
        containerCgPath: String?,
        cgroupRo: Boolean,
    ) {
        if (containerCgPath == null) return
        val src = "/sys/fs/cgroup$containerCgPath"
        if (PosixIO.access(arena, src, Constants.F_OK) == 0) {
            if (Libc.mount(arena, src, cg, null,
                    Constants.MS_BIND or Constants.MS_REC, null) == 0) {
                var remountFlags = Constants.MS_BIND or Constants.MS_REMOUNT or
                    Constants.MS_NOSUID or Constants.MS_NODEV or Constants.MS_NOEXEC
                if (cgroupRo) remountFlags = remountFlags or Constants.MS_RDONLY
                Libc.mount(arena, null, cg, null, remountFlags, null)
                Logger.debug("bound /sys/fs/cgroup from $src" +
                    if (cgroupRo) " (ro)" else " (rw)")
            } else {
                Logger.warn("bind /sys/fs/cgroup from $src: ${Libc.strerror(Libc.errno())}")
            }
        } else {
            Logger.debug("cgroup source $src does not exist (yet)")
        }
    }

    private fun readContainerCgroupPath(): String? {
        try {
            for (line in Files.readAllLines(Path.of("/proc/self/cgroup"))) {
                if (line.startsWith("0::")) {
                    val p = line.substring(3).trim()
                    return p.ifEmpty { null }
                }
            }
        } catch (_: IOException) {
        }
        return null
    }

    /**
     * Apply spec.mounts in order. Package-visible so the unit test can drive
     * this directly against a RecordingSyscalls fake -- the previous private
     * signature meant this loop was only reachable via the full Rootfs.prepare
     * path which can't be unit-tested.
     */
    internal fun applyOciMounts(
        rootfsPath: String,
        mounts: List<Spec.Mount>,
        idmapFds: Map<String, Int>,
        idmapUsernsFds: Map<String, IntArray>?,
        bindSourceFds: Map<String, Int>?,
        spec: Spec,
    ) {
        val sc = SyscallHost.current()
        for (m in mounts) {
            val rawDest = m.destination ?: continue
            // Strip rootfs prefix from destination if present. The OCI spec
            // says destination is a container-absolute path ("/mnt/x"), but
            // some callers (e.g. runc integration tests) pass host-absolute
            // paths like "$rootfs/mnt/x" where $rootfs is the host rootfs
            // directory. This matches runc's LexicallyStripRoot behaviour.
            var dest = rawDest
            if (dest.startsWith("$rootfsPath/")) {
                dest = dest.substring(rootfsPath.length)
            } else if (dest == rootfsPath) {
                dest = "/"
            }
            // skip already-handled paths
            if (dest == "/proc" || dest == "/dev"
                || dest == "/sys" || dest == "/dev/shm"
                || dest == "/dev/pts" || dest == "/dev/mqueue"
                || dest == "/sys/fs/cgroup") continue
            // Resolve symlinks in the destination path within the rootfs
            // scope, so bind mounts through dangling symlinks end up at the
            // correct host-side path. The resolved target is used for both
            // mkdir and mount(2); the original destination stays for logging.
            val resolved = resolveInRootfs(rootfsPath, dest)
            val target = resolved
            val type = m.type ?: "none"
            val parsed = MountOptions.parse(m.options)
            val flags = parsed.flags
            val propagation = parsed.propagation
            var data = parsed.data
            val isBind = parsed.isBind
            // Create the target mount point. For bind mounts where the source
            // is a regular file, create a file (not a directory). runc follows
            // symlinks in the destination path within the rootfs and creates
            // intermediate directories as needed.
            val targetExisted = Files.isDirectory(Path.of(target))
            createMountTarget(rootfsPath, m, target, isBind)

            // Id-mapped mounts: if uidMappings/gidMappings are present (or the
            // "idmap"/"ridmap" option is set) we route the bind through
            // open_tree + mount_setattr(MOUNT_ATTR_IDMAP) + move_mount.
            // When "idmap"/"ridmap" is in the options but no mount-level mappings
            // are provided, the container's userns mappings are used (implied).
            // Prefer the host-prepared fd that CreateCommand stashed in idmapFds.
            val hasExplicitMappings = m.uidMappings?.isNotEmpty() == true
            val wantIdmap = hasExplicitMappings || parsed.isIdmap || parsed.isRecursiveIdmap
            if (wantIdmap && isBind) {
                val recursive = parsed.isRecursiveIdmap
                // When the bind is recursive (rbind / MS_REC), pass
                // AT_RECURSIVE to open_tree so the clone captures
                // submounts created by earlier entries in this mount
                // loop. Without this, only the top-level mount is
                // cloned and deeply nested paths become invisible.
                val cloneRecursive = (flags and Constants.MS_REC) != 0L
                // For implied mapping, synthesize a mount with the container's
                // userns mappings so IdmapHelper can create the right userns.
                var effectiveMount = m
                if (!hasExplicitMappings && (parsed.isIdmap || parsed.isRecursiveIdmap)) {
                    effectiveMount = Spec.Mount().also {
                        it.source = m.source
                        it.destination = m.destination
                        it.type = m.type
                        it.options = m.options
                        val linux = spec.linux
                        if (linux != null) {
                            it.uidMappings = linux.uidMappings
                            it.gidMappings = linux.gidMappings
                        }
                    }
                }
                val prepFd = idmapFds[m.destination]
                val deferredInfo = idmapUsernsFds?.get(m.destination)
                val done: Boolean
                if (prepFd != null) {
                    // The host-side CreateCommand already did open_tree +
                    // mount_setattr(MOUNT_ATTR_IDMAP), so prepFd is a
                    // ready-to-install tree fd. Just move_mount it.
                    done = IdmapMount.moveMount(prepFd, target)
                    PosixIO.close(prepFd)
                    if (done) Logger.debug("idmap mounted ${m.destination}" +
                        " using host-prepared tree fd $prepFd")
                } else if (deferredInfo != null) {
                    // Container-internal source: open_tree locally (earlier
                    // mounts in this loop made the source visible), then apply
                    // the id-map using the userns fd inherited from the host.
                    val usernsFd = deferredInfo[0]
                    val deferRecursive = deferredInfo[1] != 0
                    val src = m.source ?: ""
                    done = IdmapMount.apply(src, usernsFd, target,
                        deferRecursive, cloneRecursive)
                    PosixIO.close(usernsFd)
                    if (done) Logger.debug("idmap mounted ${m.destination}" +
                        " using deferred userns fd (container-internal source)")
                } else {
                    done = IdmapHelper.apply(effectiveMount, target,
                        recursive, cloneRecursive)
                    if (done) Logger.debug("idmap mounted ${m.destination}" +
                        " using in-init helper")
                }
                if (done) {
                    // Apply post-mount operations that a regular bind mount
                    // would get below. The idmap path skips the initial
                    // mount(2) call but the mount still needs propagation,
                    // VFS-flag remounting, and recursive mount attributes.
                    val vfsIdmap = Constants.MS_RDONLY or Constants.MS_NOSUID or
                        Constants.MS_NODEV or Constants.MS_NOEXEC or
                        Constants.MS_NOATIME or Constants.MS_RELATIME or
                        Constants.MS_STRICTATIME or Constants.MS_NOSYMFOLLOW or
                        Constants.MS_NODIRATIME
                    if ((flags and vfsIdmap) != 0L || parsed.clearedFlags != 0L) {
                        val remountFlags = Constants.MS_BIND or Constants.MS_REMOUNT or
                            (flags and vfsIdmap)
                        if (sc.mount(null, target, null, remountFlags, null) != 0) {
                            Logger.debug("bind remount with access flags on " +
                                "${m.destination} (idmap) failed: ${sc.strerror(sc.errno())}")
                        }
                    }
                    if (propagation != 0L) {
                        if (sc.mount(null, target, null, propagation, null) != 0) {
                            Logger.debug("propagation set on ${m.destination}" +
                                " (idmap) failed: ${sc.strerror(sc.errno())}")
                        }
                    }
                    if (parsed.hasRecAttr()) {
                        mountSetattr(target, parsed.recAttrSet, parsed.recAttrClr)
                    }
                    continue
                }
                Logger.warn("idmap mount failed for ${m.destination}, falling back to plain bind")
            }

            // runc compat: for tmpfs mounts without an explicit "mode=" option,
            // inherit the permission bits from the existing target directory.
            // This makes "mount tmpfs on /tmp" keep /tmp's chmod'd mode.
            // Only inherit when the target directory existed BEFORE createMountTarget
            // made it; freshly-created directories would just reflect the default
            // mkdir mode (755) which is not the user's intent.
            if ("tmpfs" == type && !isBind && targetExisted) {
                data = inheritTmpfsMode(target, data)
            }

            // tmpcopyup: snapshot directory contents before tmpfs hides them.
            var tmpcopyupSnapshot: MutableList<Array<Any?>>? = null
            if (parsed.tmpcopyup && "tmpfs" == type && !isBind
                && Files.isDirectory(Path.of(target))) {
                tmpcopyupSnapshot = snapshotDirectory(Path.of(target))
            }

            // Pre-opened bind source fd: the host used open_tree(OPEN_TREE_CLONE)
            // to create a detached mount tree fd for sources that become
            // inaccessible inside the user namespace. Attach it via move_mount.
            val bindSrcFd = if (isBind && bindSourceFds != null) {
                bindSourceFds[m.destination]
            } else null
            if (bindSrcFd != null) {
                val ok = IdmapMount.moveMount(bindSrcFd, target)
                PosixIO.close(bindSrcFd)
                if (ok) {
                    Logger.debug("move_mount bind source fd $bindSrcFd -> ${m.destination}")
                    val vfsBind = Constants.MS_RDONLY or Constants.MS_NOSUID or
                        Constants.MS_NODEV or Constants.MS_NOEXEC or
                        Constants.MS_NOATIME or Constants.MS_RELATIME or
                        Constants.MS_STRICTATIME or Constants.MS_NOSYMFOLLOW or
                        Constants.MS_NODIRATIME
                    if ((flags and vfsBind) != 0L || parsed.clearedFlags != 0L) {
                        val remountFlags = Constants.MS_BIND or Constants.MS_REMOUNT or
                            (flags and vfsBind)
                        if (sc.mount(null, target, null, remountFlags, null) != 0) {
                            Logger.debug("bind remount on ${m.destination}" +
                                " (bind-source-fd) failed: ${sc.strerror(sc.errno())}")
                        }
                    }
                    if (propagation != 0L) {
                        if (sc.mount(null, target, null, propagation, null) != 0) {
                            Logger.debug("propagation on ${m.destination}" +
                                " (bind-source-fd) failed: ${sc.strerror(sc.errno())}")
                        }
                    }
                    if (parsed.hasRecAttr()) {
                        mountSetattr(target, parsed.recAttrSet, parsed.recAttrClr)
                    }
                    continue
                }
                Logger.warn("move_mount for ${m.destination} failed, falling back to regular mount")
            }
            var mountSource = m.source
            if (isBind && mountSource != null
                && !File(mountSource).exists()
                && File("$rootfsPath$mountSource").exists()) {
                // Container bind-mount source: when the source path does not
                // exist on the host but DOES exist under the rootfs, it refers
                // to a location created by an earlier mount in the same spec
                // (e.g. a tmpfs or another bind). Resolve it rootfs-relative
                // so the mount sees the right content. This matches runc.
                mountSource = "$rootfsPath$mountSource"
                Logger.debug("resolved container bind source ${m.source} -> $mountSource")
            }
            val rc = sc.mount(mountSource, target, if (isBind) null else type, flags, data)
            if (rc != 0) {
                Logger.debug("optional mount ${m.destination} failed: ${sc.strerror(sc.errno())}")
                continue
            }
            Logger.debug("mounted ${m.destination} (type=$type)")

            // tmpcopyup: restore pre-existing contents into the fresh tmpfs.
            if (!tmpcopyupSnapshot.isNullOrEmpty()) {
                restoreDirectory(Path.of(target), tmpcopyupSnapshot)
                Logger.debug("tmpcopyup restored contents into ${m.destination}")
            }
            // bind mounts ignore MS_RDONLY (and other access flags) on the initial
            // mount; the kernel just bind-attaches the source as-is. A second
            // MS_BIND|MS_REMOUNT with the desired flags is required to actually
            // enforce them. This also handles "clearing" flags: e.g. "bind,dev"
            // means clear MS_NODEV by not including it in the remount.
            val vfsFlags = Constants.MS_RDONLY or Constants.MS_NOSUID or
                Constants.MS_NODEV or Constants.MS_NOEXEC or
                Constants.MS_NOATIME or Constants.MS_RELATIME or
                Constants.MS_STRICTATIME or Constants.MS_NOSYMFOLLOW or
                Constants.MS_NODIRATIME
            if (isBind && ((flags and vfsFlags) != 0L || parsed.clearedFlags != 0L)) {
                val remountFlags = Constants.MS_BIND or Constants.MS_REMOUNT or
                    (flags and vfsFlags)
                if (sc.mount(null, target, null, remountFlags, null) != 0) {
                    Logger.debug("bind remount with access flags on ${m.destination}" +
                        " failed: ${sc.strerror(sc.errno())}")
                }
            }
            // Apply per-mount propagation if requested. propagation flag has to be set
            // alone via a second mount() call.
            if (propagation != 0L) {
                if (sc.mount(null, target, null, propagation, null) != 0) {
                    Logger.debug("propagation set on ${m.destination} failed: " +
                        sc.strerror(sc.errno()))
                }
            }
            // Recursive mount attributes (rro, rnoatime, etc.) require the
            // mount_setattr(2) syscall with AT_RECURSIVE, applied after the
            // regular mount(2). This makes the attribute change propagate to
            // all submounts recursively.
            if (parsed.hasRecAttr()) {
                mountSetattr(target, parsed.recAttrSet, parsed.recAttrClr)
            }
        }
    }

    fun pivot(newRoot: String, rootfsPropagation: String?) {
        Arena.ofConfined().use { arena ->
            Logger.debug("pivot_root to $newRoot")
            // Open "/" BEFORE pivot so we have an fd to the old root.
            // After pivot_root, this fd still references the old root mount.
            val oldrootFd = PosixIO.open(arena, "/",
                Constants.O_DIRECTORY or Constants.O_RDONLY, 0)
            if (oldrootFd < 0) {
                throw RuntimeException("open /: ${Libc.strerror(Libc.errno())}")
            }
            // Also open the new root to fchdir into it for pivot_root(".", ".").
            val newrootFd = PosixIO.open(arena, newRoot,
                Constants.O_DIRECTORY or Constants.O_RDONLY, 0)
            if (newrootFd < 0) {
                PosixIO.close(oldrootFd)
                throw RuntimeException("open $newRoot: ${Libc.strerror(Libc.errno())}")
            }
            try {
                // fchdir to new root so pivot_root(".", ".") acts on it.
                if (PosixIO.fchdir(newrootFd) != 0) {
                    throw RuntimeException("fchdir newroot: ${Libc.strerror(Libc.errno())}")
                }
                if (Libc.pivotRoot(arena, ".", ".") != 0) {
                    throw RuntimeException("pivot_root: ${Libc.strerror(Libc.errno())}")
                }
                // After pivot_root(".", "."), cwd is the old root (kernel
                // behavior). fchdir to the old root fd to be safe, then make
                // the old root (and all its children) MS_SLAVE recursively
                // so our unmount doesn't propagate to the host. This targets
                // the OLD root only, preserving propagation flags on mounts
                // under the NEW root (e.g. MS_SHARED on idmap mounts).
                if (PosixIO.fchdir(oldrootFd) != 0) {
                    throw RuntimeException("fchdir oldroot: ${Libc.strerror(Libc.errno())}")
                }
                if (Libc.mount(arena, null, ".", null,
                        Constants.MS_SLAVE or Constants.MS_REC, null) != 0) {
                    Logger.warn("remount oldroot as slave failed: ${Libc.strerror(Libc.errno())}")
                }
                if (Libc.umount2(arena, ".", Constants.MNT_DETACH) != 0) {
                    Logger.warn("umount2 oldroot failed: ${Libc.strerror(Libc.errno())}")
                }
            } finally {
                PosixIO.close(newrootFd)
                PosixIO.close(oldrootFd)
            }
            if (Libc.chdir(arena, "/") != 0) {
                throw RuntimeException("chdir /: ${Libc.strerror(Libc.errno())}")
            }
            // Apply spec.linux.rootfsPropagation to the new "/" -- this is the
            // user-visible propagation mode inside the container. It has to
            // happen post-pivot because pivot_root rejects MS_SHARED on the
            // new root and its parent.
            if (rootfsPropagation != null) {
                var prop = MountOptions.propagationFlag(rootfsPropagation)
                if (prop != 0L) {
                    // runc compat: rootfsPropagation is always applied
                    // recursively, regardless of whether the config value
                    // uses the "r" prefix or not.
                    prop = prop or Constants.MS_REC
                    // The kernel's MS_SHARED does NOT clear an existing slave
                    // relationship, resulting in shared+slave instead of pure
                    // shared. Clear any slave state with MS_PRIVATE first so
                    // the final propagation is exactly what the spec requests.
                    // Only needed for MS_SHARED; the kernel's MS_PRIVATE and
                    // MS_SLAVE already handle existing relationships correctly.
                    if ((prop and Constants.MS_SHARED) != 0L) {
                        Libc.mount(arena, null, "/", null,
                            Constants.MS_PRIVATE or Constants.MS_REC, null)
                    }
                    if (Libc.mount(arena, null, "/", null, prop, null) != 0) {
                        Logger.warn("set / to $rootfsPropagation failed: " +
                            Libc.strerror(Libc.errno()))
                    } else {
                        Logger.debug("/ propagation set to $rootfsPropagation")
                    }
                }
            }
            Logger.debug("pivot_root completed")
        }
    }

    /**
     * Alternative to [pivot] when `--no-pivot` is requested.
     * Moves the rootfs mount to "/" via `mount(MS_MOVE)` and then
     * calls `chroot(".")` + `chdir("/")`. This is the same
     * approach runc uses in its `msMoveRoot` function.
     *
     * Unlike pivot_root, this does NOT detach the old root. The old root's
     * mounts remain in the mount namespace (but are inaccessible from
     * userspace because they're hidden under the new root).
     */
    fun msMoveRoot(newRoot: String, rootfsPropagation: String?) {
        Arena.ofConfined().use { arena ->
            Logger.debug("msMoveRoot (no-pivot) to $newRoot")

            // Before MS_MOVE, mask host procfs and sysfs mounts. runc
            // lazy-unmounts them so the container cannot re-mount procfs
            // writable (which would expose bare /proc). Collect targets
            // first because /proc/self/mountinfo disappears after unmount.
            val toUnmount = mutableListOf<String>()
            try {
                for (line in Files.readAllLines(Path.of("/proc/self/mountinfo"))) {
                    val parts = line.split(" ")
                    if (parts.size < 9) continue
                    val root = parts[3]
                    val mountPoint = parts[4]
                    var dashIdx = -1
                    for (i in 6 until parts.size) {
                        if ("-" == parts[i]) { dashIdx = i; break }
                    }
                    if (dashIdx < 0 || dashIdx + 1 >= parts.size) continue
                    val fstype = parts[dashIdx + 1]
                    if ("/" != root) continue
                    if ("proc" != fstype && "sysfs" != fstype) continue
                    if (mountPoint.startsWith(newRoot)) continue
                    toUnmount += mountPoint
                }
            } catch (e: IOException) {
                Logger.warn("msMoveRoot: failed to read mountinfo: ${e.message}")
            }
            for (mp in toUnmount) {
                Libc.mount(arena, null, mp, null,
                    Constants.MS_SLAVE or Constants.MS_REC, null)
                if (Libc.umount2(arena, mp, Constants.MNT_DETACH) != 0) {
                    Libc.mount(arena, "tmpfs", mp, "tmpfs", 0, null)
                    Logger.debug("covered $mp with tmpfs")
                } else {
                    Logger.debug("lazy-unmounted host mount at $mp")
                }
            }

            // Grab an fd to the rootfs BEFORE MS_MOVE. After the move, the
            // process cwd/root still reference the ORIGINAL root mount (now
            // covered by the rootfs mount). Path-based chdir("/") would stay
            // on the original root because "/" resolves to the process root
            // without mount traversal. Using fchdir(fd) sidesteps this: the
            // fd follows the mount wherever it goes.
            val rootFd = PosixIO.open(arena, newRoot,
                Constants.O_DIRECTORY or Constants.O_RDONLY, 0)
            if (rootFd < 0) {
                throw RuntimeException("open $newRoot: ${Libc.strerror(Libc.errno())}")
            }

            if (Libc.mount(arena, newRoot, "/", null, Constants.MS_MOVE, null) != 0) {
                PosixIO.close(rootFd)
                throw RuntimeException("mount MS_MOVE $newRoot to /: ${Libc.strerror(Libc.errno())}")
            }

            // fchdir to the rootfs mount (fd follows the MS_MOVE), then
            // chroot(".") to lock the root. Finally chdir("/") for sanity.
            if (PosixIO.fchdir(rootFd) != 0) {
                PosixIO.close(rootFd)
                throw RuntimeException("fchdir: ${Libc.strerror(Libc.errno())}")
            }
            PosixIO.close(rootFd)
            if (Libc.chroot(arena, ".") != 0) {
                throw RuntimeException("chroot: ${Libc.strerror(Libc.errno())}")
            }
            if (Libc.chdir(arena, "/") != 0) {
                throw RuntimeException("chdir /: ${Libc.strerror(Libc.errno())}")
            }
            // Apply rootfsPropagation the same way as pivot().
            if (rootfsPropagation != null) {
                var prop = MountOptions.propagationFlag(rootfsPropagation)
                if (prop != 0L) {
                    prop = prop or Constants.MS_REC
                    if ((prop and Constants.MS_SHARED) != 0L) {
                        Libc.mount(arena, null, "/", null,
                            Constants.MS_PRIVATE or Constants.MS_REC, null)
                    }
                    if (Libc.mount(arena, null, "/", null, prop, null) != 0) {
                        Logger.warn("set / to $rootfsPropagation failed: " +
                            Libc.strerror(Libc.errno()))
                    } else {
                        Logger.debug("/ propagation set to $rootfsPropagation")
                    }
                }
            }
            Logger.debug("msMoveRoot completed")
        }
    }

    fun setRootReadonly() {
        Arena.ofConfined().use { arena ->
            // Preserve MS_NOSUID we set earlier -- MS_REMOUNT replaces the flag set
            // wholesale, so we must include every flag we want to keep on.
            val flags = Constants.MS_BIND or Constants.MS_REMOUNT or
                Constants.MS_RDONLY or Constants.MS_NOSUID
            if (Libc.mount(arena, null, "/", null, flags, null) != 0) {
                Logger.warn("remount / readonly failed: ${Libc.strerror(Libc.errno())}")
            } else {
                Logger.debug("/ set readonly+nosuid")
            }
        }
    }

    /**
     * Mask sensitive paths by bind-mounting /dev/null over files and a tmpfs over
     * directories. Used to hide /proc/kcore etc.
     */
    fun maskPaths(paths: List<String>?) {
        if (paths == null) return
        val sc = SyscallHost.current()
        // runc compat: deduplicate paths so each is masked exactly once.
        val deduped = LinkedHashSet(paths)
        // runc mounts a single tmpfs for all directory masks and bind-mounts
        // it onto each target, so all share the same device number.
        var tmpfsSource: String? = null
        for (p in deduped) {
            val rc = sc.mount("/dev/null", p, null, Constants.MS_BIND, null)
            if (rc == 0) {
                Logger.debug("masked $p with /dev/null")
                continue
            }
            val err = sc.errno()
            if (err == Constants.ENOENT) continue // skip nonexistent
            // Likely a directory. Mount a single shared tmpfs on the first
            // directory, then bind-mount it onto subsequent directories so
            // all directory masks share the same device number (runc compat).
            if (tmpfsSource == null) {
                val rc2 = sc.mount("tmpfs", p, "tmpfs", Constants.MS_RDONLY, null)
                if (rc2 != 0) {
                    Logger.debug("mask $p failed: ${sc.strerror(sc.errno())}")
                } else {
                    tmpfsSource = p
                    Logger.debug("masked $p with tmpfs")
                }
            } else {
                val rc2 = sc.mount(tmpfsSource, p, null,
                    Constants.MS_BIND or Constants.MS_RDONLY, null)
                if (rc2 != 0) {
                    Logger.debug("mask bind $p failed: ${sc.strerror(sc.errno())}")
                } else {
                    Logger.debug("masked $p via bind from $tmpfsSource")
                }
            }
        }
    }

    /** Bind-remount each path read-only. Used for /proc/bus, /proc/sys etc. */
    fun readonlyRemount(paths: List<String>?) {
        if (paths == null) return
        val sc = SyscallHost.current()
        for (p in paths) {
            // First bind it to itself so we can remount RO without affecting host.
            if (sc.mount(p, p, null, Constants.MS_BIND or Constants.MS_REC, null) != 0) {
                val err = sc.errno()
                if (err == Constants.ENOENT) continue
                Logger.debug("rebind $p: ${sc.strerror(err)}")
                continue
            }
            val flags = Constants.MS_BIND or Constants.MS_REC or Constants.MS_REMOUNT or
                Constants.MS_RDONLY
            if (sc.mount(p, p, null, flags, null) != 0) {
                Logger.debug("readonly remount $p: ${sc.strerror(sc.errno())}")
            } else {
                Logger.debug("readonly $p")
            }
        }
    }

    /**
     * Create the mount target directory or file at the already-resolved host
     * path [target]. For bind mounts where the source is a regular file,
     * create a file (not a directory).
     */
    private fun createMountTarget(
        rootfsPath: String,
        m: Spec.Mount,
        target: String,
        isBind: Boolean,
    ) {
        try {
            var isFile = false
            if (isBind && m.source != null) {
                var srcPath = Path.of(m.source)
                if (!srcPath.isAbsolute) {
                    srcPath = Path.of(System.getProperty("user.dir", ".")).resolve(srcPath)
                }
                if (Files.isRegularFile(srcPath)) {
                    isFile = true
                }
            }
            val targetPath = Path.of(target)
            if (isFile) {
                Files.createDirectories(targetPath.parent)
                if (!Files.exists(targetPath)) {
                    Files.createFile(targetPath)
                }
            } else {
                Files.createDirectories(targetPath)
            }
        } catch (_: IOException) {
            try {
                Files.createDirectories(Path.of(target))
            } catch (_: IOException) {
            }
        }
    }

    /**
     * Resolve a container-relative path within rootfsPath, following symlinks
     * component by component but keeping the result under rootfsPath.
     * Returns the fully resolved host-side path.
     *
     * When a symlink target is itself an absolute path (e.g. /tmp/foo), it
     * is re-rooted under rootfsPath. Its components are then resolved
     * recursively so multi-hop chains (A -> /B -> /C/D) work.
     */
    private fun resolveInRootfs(rootfsPath: String, destination: String): String {
        val rootfs = Path.of(rootfsPath)
        return resolveComponents(rootfs, destination.split("/").toTypedArray(), 0, rootfs, 0).toString()
    }

    private fun resolveComponents(
        rootfs: Path,
        components: Array<String>,
        startIdx: Int,
        current: Path,
        depth: Int,
    ): Path {
        if (depth > 255) return current // symlink loop guard
        var cur = current
        for (i in startIdx until components.size) {
            val comp = components[i]
            if (comp.isEmpty()) continue
            val next = cur.resolve(comp)
            if (Files.isSymbolicLink(next)) {
                try {
                    val linkTarget = Files.readSymbolicLink(next)
                    val base = if (linkTarget.isAbsolute) rootfs else cur
                    // Resolve the symlink target's components recursively so
                    // multi-hop chains are followed correctly.
                    var linkStr = linkTarget.toString()
                    if (linkTarget.isAbsolute) linkStr = linkStr.substring(1)
                    val linkParts = linkStr.split("/").toTypedArray()
                    // Concatenate remaining original components after the link parts.
                    val remaining = components.size - i - 1
                    val merged = Array(linkParts.size + remaining) { idx ->
                        if (idx < linkParts.size) linkParts[idx]
                        else components[i + 1 + (idx - linkParts.size)]
                    }
                    val resolved = resolveComponents(rootfs, merged, 0, base, depth + 1)
                    // Security: ensure we're still under rootfs.
                    if (!resolved.normalize().startsWith(rootfs)) return rootfs
                    return resolved
                } catch (_: IOException) {
                    cur = next
                }
            } else {
                cur = next
            }
        }
        return cur
    }

    /**
     * runc compat: for tmpfs mounts, if no explicit "mode=" is in the data
     * string, read the existing target directory's permission bits and inject
     * "mode=<octal>" so the tmpfs inherits them. Without this, tmpfs defaults
     * to mode 1777, losing any chmod the user applied to the directory before
     * mounting.
     */
    private fun inheritTmpfsMode(target: String, data: String?): String? {
        if (data != null && "mode=" in data) return data
        return try {
            val unixMode = Files.getAttribute(Path.of(target), "unix:mode",
                LinkOption.NOFOLLOW_LINKS) as Int
            val mode = unixMode and 0xfff /* 07777 */
            val modeStr = "mode=0${Integer.toOctalString(mode)}"
            Logger.debug("tmpfs inheriting $modeStr from $target")
            if (data.isNullOrEmpty()) modeStr else "$data,$modeStr"
        } catch (e: Exception) {
            Logger.debug("could not read target mode for tmpfs: ${e.message}")
            data
        }
    }

    /**
     * Snapshot a directory tree into a list of entries, each represented as
     * `{type, relativePath, payload, mode}`. Types are "dir", "file",
     * or "symlink". Payload is `ByteArray` for files, a symlink-target
     * string for symlinks, and null for directories. Mode is the Unix
     * permission bits (int), preserved so tmpcopyup restores chmod'd modes.
     */
    private fun snapshotDirectory(dir: Path): MutableList<Array<Any?>> {
        val entries = mutableListOf<Array<Any?>>()
        if (!Files.isDirectory(dir)) return entries
        try {
            Files.walk(dir).use { walk ->
                walk.forEach { p ->
                    if (p == dir) return@forEach
                    val rel = dir.relativize(p).toString()
                    try {
                        var mode = -1
                        try {
                            mode = (Files.getAttribute(p, "unix:mode",
                                LinkOption.NOFOLLOW_LINKS) as Int) and 0xfff /* 07777 */
                        } catch (_: Exception) {
                        }
                        when {
                            Files.isSymbolicLink(p) ->
                                entries += arrayOf<Any?>("symlink", rel,
                                    Files.readSymbolicLink(p).toString(), mode)
                            Files.isDirectory(p) ->
                                entries += arrayOf<Any?>("dir", rel, null, mode)
                            Files.isRegularFile(p) ->
                                entries += arrayOf<Any?>("file", rel,
                                    Files.readAllBytes(p), mode)
                        }
                    } catch (_: IOException) {
                    }
                }
            }
        } catch (_: IOException) {
        }
        return entries
    }

    /**
     * Restore a snapshot produced by [snapshotDirectory] into the
     * given target directory (typically a freshly-mounted tmpfs), preserving
     * Unix permission bits.
     */
    private fun restoreDirectory(dir: Path, entries: List<Array<Any?>>) {
        for (e in entries) {
            val type = e[0] as String
            val target = dir.resolve(e[1] as String)
            val mode = e[3] as Int
            try {
                when (type) {
                    "dir" -> {
                        Files.createDirectories(target)
                        if (mode >= 0) {
                            Files.setPosixFilePermissions(target,
                                PosixFilePermissions.fromString(modeToPerms(mode)))
                        }
                    }
                    "file" -> {
                        Files.createDirectories(target.parent)
                        Files.write(target, e[2] as ByteArray)
                        if (mode >= 0) {
                            Files.setPosixFilePermissions(target,
                                PosixFilePermissions.fromString(modeToPerms(mode)))
                        }
                    }
                    "symlink" -> {
                        Files.createDirectories(target.parent)
                        if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                            Files.createSymbolicLink(target, Path.of(e[2] as String))
                        }
                    }
                }
            } catch (ex: IOException) {
                Logger.debug("tmpcopyup restore ${e[1]}: ${ex.message}")
            }
        }
    }

    /** Convert a Unix permission mode (0777, etc.) to a PosixFilePermissions string. */
    private fun modeToPerms(mode: Int): String {
        val p = CharArray(9)
        p[0] = if (mode and 0x100 /* 0400 */ != 0) 'r' else '-'
        p[1] = if (mode and 0x80  /* 0200 */ != 0) 'w' else '-'
        p[2] = if (mode and 0x40  /* 0100 */ != 0) 'x' else '-'
        p[3] = if (mode and 0x20  /* 0040 */ != 0) 'r' else '-'
        p[4] = if (mode and 0x10  /* 0020 */ != 0) 'w' else '-'
        p[5] = if (mode and 0x8   /* 0010 */ != 0) 'x' else '-'
        p[6] = if (mode and 0x4   /* 0004 */ != 0) 'r' else '-'
        p[7] = if (mode and 0x2   /* 0002 */ != 0) 'w' else '-'
        p[8] = if (mode and 0x1   /* 0001 */ != 0) 'x' else '-'
        return String(p)
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
    private fun mountSetattr(target: String, attrSet: Long, attrClr: Long) {
        Arena.ofConfined().use { arena ->
            val attr = arena.allocate(32)
            attr.set(ValueLayout.JAVA_LONG, 0, attrSet)
            attr.set(ValueLayout.JAVA_LONG, 8, attrClr)
            attr.set(ValueLayout.JAVA_LONG, 16, 0L) // propagation
            attr.set(ValueLayout.JAVA_LONG, 24, 0L) // userns_fd
            val path = arena.allocateFrom(target)
            val rc = Libc.syscall(
                Constants.NR_mount_setattr,
                -1, path.address(), Constants.AT_RECURSIVE.toLong(), attr.address(), 32
            )
            if (rc != 0L) {
                Logger.debug("mount_setattr(AT_RECURSIVE) on $target failed: " +
                    Libc.strerror(Libc.errno()))
            } else {
                Logger.debug("mount_setattr(AT_RECURSIVE) applied on $target" +
                    " set=0x${java.lang.Long.toHexString(attrSet)}" +
                    " clr=0x${java.lang.Long.toHexString(attrClr)}")
            }
        }
    }
}
