package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.ipc.NotifySocket;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.process.MainProcess;
import com.ternbusty.takoyaki.process.NamespaceFlags;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.util.Json;

import java.lang.foreign.Arena;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

public final class CreateCommand {
    private CreateCommand() {}

    public static int run(String rootPath, boolean debug, String containerId,
                          String bundleIn, String pidFile, String consoleSocket,
                          boolean noPivot, boolean noNewKeyring, int preserveFds,
                          String pidfdSocket) {
        if (State.exists(rootPath, containerId)) {
            System.err.println("container " + containerId + " already exists");
            return 1;
        }

        // Resolve bundle to an absolute path so later commands (start/delete) can
        // re-open config.json regardless of their cwd.
        String bundle;
        try {
            bundle = Path.of(bundleIn).toAbsolutePath().normalize().toString();
        } catch (Exception e) {
            System.err.println("invalid bundle path: " + e.getMessage());
            return 1;
        }

        Spec spec;
        try {
            spec = Json.readFile(Path.of(bundle, "config.json"), Spec::fromJson);
        } catch (java.nio.file.NoSuchFileException e) {
            System.err.println(bundle + " does not exist");
            return 1;
        } catch (Exception e) {
            System.err.println("failed to load config.json: " + e.getMessage());
            return 1;
        }

        // OCI spec: the runtime MUST reject configs that contain invalid /
        // unsupported values. ociVersion must be a semver-like string. Anything
        // else (e.g. "invalid" — runtime-tools misc_props test) is rejected.
        if (spec.ociVersion == null
                || !spec.ociVersion.matches("\\d+\\.\\d+(\\.\\d+)?(-[\\w.+-]+)?")) {
            System.err.println("invalid ociVersion: " + spec.ociVersion);
            return 1;
        }

        // runc compat: SCHED_DEADLINE cannot be used with CPU pinning.
        if (spec.process != null && spec.process.scheduler != null
                && "SCHED_DEADLINE".equals(spec.process.scheduler.policy)
                && spec.linux != null && spec.linux.resources != null
                && spec.linux.resources.cpu != null
                && spec.linux.resources.cpu.cpus != null
                && !spec.linux.resources.cpu.cpus.isEmpty()) {
            System.err.println("process scheduler can't be used together with AllowedCPUs");
            return 1;
        }

        // Note on process.args validation: runtime-tools' validation/start
        // test 7 sets spec.process = nil and expects create to SUCCEED and
        // start to return an error (the spec is ambiguous on which phase
        // validates, but the conformance suite settles it). We therefore
        // defer this check to StartCommand below.

        // Note: when process.terminal is true and no --console-socket is given,
        // runc handles it internally for foreground runs (runc run without -d).
        // Since CreateCommand is called from both `create` and `run`, we do not
        // enforce console-socket presence here. Without it, InitProcess simply
        // skips pty setup and the process inherits its parent's stdio.

        String rootfsPath = spec.root.path.startsWith("/")
                ? spec.root.path
                : bundle + "/" + spec.root.path;
        Logger.debug("rootfs=" + rootfsPath);

        String notifySocketPath = NotifySocket.pathFor(containerId);
        int notifyListenerFd = NotifySocket.createListener(notifySocketPath);

        int[] syncFds = new int[2];
        int[] mainFds = new int[2];
        try (Arena arena = Arena.ofConfined()) {
            if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, syncFds) < 0) {
                System.err.println("socketpair sync failed: " + Libc.strerror(Libc.errno()));
                return 1;
            }
            if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, mainFds) < 0) {
                System.err.println("socketpair main failed: " + Libc.strerror(Libc.errno()));
                return 1;
            }
        }
        int mainParentFd = mainFds[0];
        int mainChildFd = mainFds[1];

        int cloneFlags = NamespaceFlags.fromSpec(spec.linux != null ? spec.linux.namespaces : null);
        Logger.debug("clone flags=0x" + Integer.toHexString(cloneFlags));

        String exePath;
        try (Arena arena = Arena.ofConfined()) {
            exePath = PosixIO.readlink(arena, "/proc/self/exe");
        }
        if (exePath == null) {
            System.err.println("readlink /proc/self/exe failed");
            return 1;
        }

        List<String> envList = HostEnv.inherited();
        envList.add("_TAKOYAKI_IS_BOOTSTRAP=1");
        envList.add("_TAKOYAKI_SYNCPIPE=" + syncFds[1]);
        envList.add("_TAKOYAKI_CLONE_FLAGS=" + Integer.toHexString(cloneFlags));
        envList.add("_TAKOYAKI_MAIN_SENDER_FD=" + mainChildFd);
        envList.add("_TAKOYAKI_NOTIFY_LISTENER_FD=" + notifyListenerFd);
        envList.add("_TAKOYAKI_BUNDLE_PATH=" + bundle);
        envList.add("_TAKOYAKI_ROOTFS_PATH=" + rootfsPath);
        envList.add("_TAKOYAKI_CONTAINER_ID=" + containerId);
        if (debug) envList.add("_TAKOYAKI_BOOTSTRAP_DEBUG=1");
        // Pass log configuration to the init process so it can redirect its
        // Logger output to the same file as the main process. Without this,
        // init's debug/warn output leaks to stderr (visible to bats tests).
        String logFilePath = Logger.getLogFilePath();
        if (logFilePath != null) envList.add("_TAKOYAKI_LOG_FILE=" + logFilePath);
        String logFmt = Logger.getFormatName();
        if (logFmt != null) envList.add("_TAKOYAKI_LOG_FORMAT=" + logFmt);
        // Pre-connect to the console socket on the HOST side so the init
        // process (which may run inside a user namespace as an unmapped uid)
        // doesn't need filesystem access to the socket path.  The connected
        // fd survives fork+execve (no CLOEXEC); InitProcess uses it directly.
        int consoleSocketFd = -1;
        if (consoleSocket != null) {
            consoleSocketFd = com.ternbusty.takoyaki.console.ConsoleSocket.connectTo(consoleSocket);
            if (consoleSocketFd >= 0) {
                envList.add("_TAKOYAKI_CONSOLE_SOCKET_FD=" + consoleSocketFd);
            } else {
                // Fall back to passing the path (non-userns case).
                envList.add("_TAKOYAKI_CONSOLE_SOCKET=" + consoleSocket);
            }
        }
        if (noNewKeyring) envList.add("_TAKOYAKI_NO_NEW_KEYRING=1");
        if (noPivot) envList.add("_TAKOYAKI_NO_PIVOT=1");

        // Namespaces with an explicit `path` field: open the path on the host so
        // bootstrap.c can join via setns() instead of unshare(). The fd survives
        // fork+execve because we don't set CLOEXEC. Names match `setns` nstype
        // constants in bootstrap.c's switch table.
        if (spec.linux != null && spec.linux.namespaces != null) {
            StringJoiner nsFds = new StringJoiner(",");
            try (Arena openArena = Arena.ofConfined()) {
                for (Spec.Namespace ns : spec.linux.namespaces) {
                    if (ns.path == null || ns.path.isEmpty()) continue;
                    int fd = PosixIO.open(openArena, ns.path, Constants.O_RDONLY, 0);
                    if (fd < 0) {
                        System.err.println("open ns path " + ns.path + " failed: " + Libc.strerror(Libc.errno()));
                        return 1;
                    }
                    nsFds.add(ns.type + ":" + fd);
                }
            }
            if (nsFds.length() > 0) {
                envList.add("_TAKOYAKI_NS_FDS=" + nsFds);
            }
        }

        // Mount idmap: prepare fully-ready open_tree fds on the HOST side.
        // mount_setattr(MOUNT_ATTR_IDMAP) requires CAP_SYS_ADMIN in init_user_ns,
        // which the container init lacks when a user namespace is in use.
        // By completing open_tree + mount_setattr here (on the host), the init
        // only needs to call move_mount with the pre-prepared fd.
        // For non-userns containers this also works correctly because CreateCommand
        // runs as root in init_user_ns.
        if (spec.mounts != null) {
            StringJoiner fdMap = new StringJoiner(",");
            StringJoiner usernsFdMap = new StringJoiner(",");
            for (Spec.Mount m : spec.mounts) {
                // Determine if this mount needs an idmap userns fd.
                // Explicit uidMappings on the mount take precedence; otherwise
                // the "idmap"/"ridmap" mount option with the container's userns
                // mappings (implied mapping).
                java.util.List<Spec.IdMapping> uidMaps = m.uidMappings;
                java.util.List<Spec.IdMapping> gidMaps = m.gidMappings;
                boolean hasExplicit = uidMaps != null && !uidMaps.isEmpty();
                boolean hasIdmapOption = false;
                boolean isRidmap = false;
                if (m.options != null) {
                    for (String opt : m.options) {
                        if ("idmap".equals(opt)) {
                            hasIdmapOption = true;
                        } else if ("ridmap".equals(opt)) {
                            hasIdmapOption = true;
                            isRidmap = true;
                        }
                    }
                }
                if (!hasExplicit && hasIdmapOption && spec.linux != null) {
                    uidMaps = spec.linux.uidMappings;
                    gidMaps = spec.linux.gidMappings;
                }

                // When joining an existing user namespace (userns path is set)
                // and no explicit mappings are available, use the joined userns's
                // fd directly for mount_setattr. Its uid_map/gid_map were already
                // set by whoever created it.
                int usernsFd = -1;
                if ((uidMaps == null || uidMaps.isEmpty()) && hasIdmapOption
                        && spec.linux != null && spec.linux.namespaces != null) {
                    for (Spec.Namespace ns : spec.linux.namespaces) {
                        if ("user".equals(ns.type) && ns.path != null && !ns.path.isEmpty()) {
                            try (Arena nsArena = Arena.ofConfined()) {
                                usernsFd = PosixIO.open(nsArena, ns.path, Constants.O_RDONLY, 0);
                            }
                            if (usernsFd < 0) {
                                Logger.warn("open joined userns " + ns.path
                                        + " for idmap failed: " + Libc.strerror(Libc.errno()));
                            }
                            break;
                        }
                    }
                }
                if (usernsFd < 0 && (uidMaps == null || uidMaps.isEmpty())) continue;

                // Step 1: create the helper userns with the desired uid/gid maps,
                // unless we already have a userns fd from joining an existing one.
                if (usernsFd < 0) {
                    usernsFd = com.ternbusty.takoyaki.rootfs.IdmapHelper.setupHostSide(
                            uidMaps, gidMaps);
                }
                if (usernsFd < 0) {
                    Logger.warn("idmap helper setup failed for " + m.destination
                            + "; mount will fall back to plain bind");
                    continue;
                }

                // Step 2: resolve the mount source to an absolute host path.
                String source = m.source;
                if (source != null && !source.isEmpty()) {
                    java.io.File srcFile = new java.io.File(source);
                    if (!srcFile.isAbsolute()) {
                        source = srcFile.getAbsolutePath();
                    }
                }

                // Step 3: determine open_tree / mount_setattr flags from options.
                com.ternbusty.takoyaki.rootfs.MountOptions.Parsed parsed =
                        com.ternbusty.takoyaki.rootfs.MountOptions.parse(m.options);
                boolean cloneRecursive =
                        (parsed.flags & com.ternbusty.takoyaki.syscall.Constants.MS_REC) != 0;
                boolean recursive = isRidmap || parsed.isRecursiveIdmap;

                // Step 4: open_tree on the source, then apply MOUNT_ATTR_IDMAP.
                // Container-internal source: when the source path is within
                // the rootfs, its content may depend on earlier mounts in the
                // spec that haven't been applied yet on the host side. Defer
                // to the init process which can do open_tree after the
                // preceding mounts have been applied in order.
                boolean deferToInit = source != null
                        && (source.startsWith(rootfsPath + "/")
                            || source.equals(rootfsPath));
                if (deferToInit) {
                    Logger.debug("source " + source + " is inside rootfs for "
                            + m.destination + "; deferring idmap to init");
                    int ufl = PosixIO.fcntl(usernsFd, Constants.F_GETFD, 0);
                    if (ufl >= 0) {
                        PosixIO.fcntl(usernsFd, Constants.F_SETFD,
                                ufl & ~Constants.FD_CLOEXEC);
                    }
                    usernsFdMap.add(java.util.Base64.getEncoder().encodeToString(
                            m.destination.getBytes()) + ":" + usernsFd
                            + ":" + (recursive ? 1 : 0));
                    continue;
                }
                int treeFd = com.ternbusty.takoyaki.rootfs.IdmapMount.openTree(
                        source, cloneRecursive);
                if (treeFd < 0) {
                    Logger.warn("open_tree(" + source + ") failed for " + m.destination
                            + "; mount will fall back to plain bind");
                    PosixIO.close(usernsFd);
                    continue;
                }
                // open_tree sets CLOEXEC by default. Clear it so the fd
                // survives fork+execve into bootstrap.c → Java init.
                int fl = PosixIO.fcntl(treeFd, Constants.F_GETFD, 0);
                if (fl >= 0) {
                    PosixIO.fcntl(treeFd, Constants.F_SETFD,
                            fl & ~Constants.FD_CLOEXEC);
                }
                if (!com.ternbusty.takoyaki.rootfs.IdmapMount.setIdmap(
                        treeFd, usernsFd, recursive)) {
                    Logger.warn("mount_setattr(IDMAP) failed for " + m.destination
                            + "; mount will fall back to plain bind");
                    PosixIO.close(treeFd);
                    PosixIO.close(usernsFd);
                    continue;
                }
                PosixIO.close(usernsFd);

                fdMap.add(java.util.Base64.getEncoder().encodeToString(
                        m.destination.getBytes()) + ":" + treeFd);
            }
            if (fdMap.length() > 0) {
                envList.add("_TAKOYAKI_IDMAP_FDS=" + fdMap);
            }
            if (usernsFdMap.length() > 0) {
                envList.add("_TAKOYAKI_IDMAP_USERNS_FDS=" + usernsFdMap);
            }
        }

        // Bind mount source fds: when a user namespace is configured, bind
        // mount sources that are inaccessible to the mapped container UID
        // must be pre-opened on the host side (as root in init_user_ns).
        // We use open_tree(OPEN_TREE_CLONE) to create a detached mount tree
        // fd, which the init process can later attach via move_mount().
        // This avoids the EINVAL that mount(2) returns when resolving
        // /proc/self/fd/N through inaccessible intermediate directories.
        boolean hasUserns = (cloneFlags & Constants.CLONE_NEWUSER) != 0
                || spec.hasNamespace("user");
        if (hasUserns && spec.mounts != null) {
            StringJoiner bindFdMap = new StringJoiner(",");
            try (Arena bindArena = Arena.ofConfined()) {
                for (Spec.Mount m : spec.mounts) {
                    if (m.source == null || m.source.isEmpty()) continue;
                    boolean isBind = false;
                    boolean isRbind = false;
                    if (m.options != null) {
                        for (String opt : m.options) {
                            if ("bind".equals(opt)) { isBind = true; }
                            if ("rbind".equals(opt)) { isBind = true; isRbind = true; }
                        }
                    }
                    if (!isBind) continue;

                    String absSource = m.source;
                    if (!new java.io.File(absSource).isAbsolute()) {
                        absSource = new java.io.File(absSource).getAbsolutePath();
                    }

                    if (PosixIO.access(bindArena, absSource, Constants.F_OK) != 0) {
                        continue;
                    }

                    // Only pre-open sources that would become inaccessible
                    // inside the user namespace. Check each intermediate
                    // directory for others-execute (o+x) permission. If all
                    // components are world-traversable, the regular mount
                    // path will work fine and pre-opening would be wrong for
                    // container-internal sources (earlier mounts in the spec
                    // that shadow the host path).
                    boolean needsPreOpen = false;
                    java.nio.file.Path srcPath = java.nio.file.Path.of(absSource);
                    for (java.nio.file.Path dir = srcPath.getParent();
                         dir != null && !"/".equals(dir.toString());
                         dir = dir.getParent()) {
                        if (!java.nio.file.Files.exists(dir)) break;
                        try {
                            int mode = ((int) java.nio.file.Files.getAttribute(
                                    dir, "unix:mode")) & 07777;
                            if ((mode & 001) == 0) {
                                needsPreOpen = true;
                                break;
                            }
                        } catch (Exception e) { break; }
                    }
                    if (!needsPreOpen) continue;

                    int srcFd = com.ternbusty.takoyaki.rootfs.IdmapMount.openTree(
                            absSource, isRbind);
                    if (srcFd < 0) {
                        Logger.warn("open_tree " + absSource + " failed; "
                                + "bind mount will be attempted directly");
                        continue;
                    }
                    // open_tree sets CLOEXEC by default. Clear it so the fd
                    // survives fork+execve into bootstrap.c → Java init.
                    int fl = PosixIO.fcntl(srcFd, Constants.F_GETFD, 0);
                    if (fl >= 0) {
                        PosixIO.fcntl(srcFd, Constants.F_SETFD,
                                fl & ~Constants.FD_CLOEXEC);
                    }
                    bindFdMap.add(java.util.Base64.getEncoder().encodeToString(
                            m.destination.getBytes()) + ":" + srcFd);
                    Logger.debug("open_tree bind source " + absSource
                            + " as fd " + srcFd + " for " + m.destination);
                }
            }
            if (bindFdMap.length() > 0) {
                envList.add("_TAKOYAKI_BIND_SOURCE_FDS=" + bindFdMap);
            }
        }

        // Seccomp notify listener: connect on the host side (where the listener
        // socket path actually resolves) and pass the connected fd to the init via
        // env. After the init pivots into the container rootfs the listener path is
        // no longer reachable, so this has to happen here.
        if (spec.linux != null && spec.linux.seccomp != null
                && spec.linux.seccomp.listenerPath != null
                && !spec.linux.seccomp.listenerPath.isEmpty()) {
            int fd = com.ternbusty.takoyaki.seccomp.SeccompListener.connectHostSide(
                    spec.linux.seccomp.listenerPath);
            if (fd >= 0) {
                envList.add("_TAKOYAKI_SECCOMP_LISTENER_FD=" + fd);
            } else {
                Logger.warn("could not connect to seccomp listener " + spec.linux.seccomp.listenerPath
                        + " from host; SCMP_ACT_NOTIFY rules will block forever");
            }
        }

        // timens offsets must be written in stage-1 of bootstrap.c BEFORE execve into
        // Java. The kernel rejects /proc/self/timens_offsets writes after exec, so the
        // Java side can never do it. Pass the offsets through env vars instead.
        if (spec.linux != null && spec.linux.timeOffsets != null) {
            Spec.TimeOffset bt = spec.linux.timeOffsets.get("boottime");
            if (bt != null) {
                envList.add("_TAKOYAKI_TIMENS_BOOTTIME_SECS=" + bt.secs);
                envList.add("_TAKOYAKI_TIMENS_BOOTTIME_NSEC=" + bt.nanosecs);
            }
            Spec.TimeOffset mt = spec.linux.timeOffsets.get("monotonic");
            if (mt != null) {
                envList.add("_TAKOYAKI_TIMENS_MONOTONIC_SECS=" + mt.secs);
                envList.add("_TAKOYAKI_TIMENS_MONOTONIC_NSEC=" + mt.nanosecs);
            }
        }
        String[] envp = envList.toArray(new String[0]);
        String[] argv = new String[]{exePath, "__init__"};

        Arena execArena = Arena.ofShared();
        PosixIO.ExecvePayload payload = PosixIO.ExecvePayload.build(execArena, exePath, argv, envp);

        int forkPid = PosixIO.fork();
        if (forkPid < 0) {
            System.err.println("fork failed: " + Libc.strerror(Libc.errno()));
            return 1;
        }
        if (forkPid == 0) {
            PosixIO.close(syncFds[0]);
            PosixIO.close(mainParentFd);
            PosixIO.invokeExecve(payload);
            PosixIO._exit(1);
            return 1;
        }

        PosixIO.close(syncFds[1]);
        PosixIO.close(mainChildFd);

        MainProcess.run(forkPid, syncFds[0], spec, containerId,
                bundle, rootPath, pidFile, notifyListenerFd, mainParentFd,
                pidfdSocket);
        return 0;
    }
}
