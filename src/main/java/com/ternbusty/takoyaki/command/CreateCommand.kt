package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.console.ConsoleSocket
import com.ternbusty.takoyaki.exeseal.ExeSeal
import com.ternbusty.takoyaki.ipc.NotifySocket
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.process.MainProcess
import com.ternbusty.takoyaki.process.NamespaceFlags
import com.ternbusty.takoyaki.rootfs.IdmapHelper
import com.ternbusty.takoyaki.rootfs.IdmapMount
import com.ternbusty.takoyaki.rootfs.MountOptions
import com.ternbusty.takoyaki.seccomp.SeccompListener
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.util.Json
import java.lang.foreign.Arena
import java.nio.file.Path
import java.util.Base64
import java.util.StringJoiner

object CreateCommand {

    fun run(
        rootPath: String, debug: Boolean, containerId: String,
        bundleIn: String, pidFile: String?, consoleSocket: String?,
        noPivot: Boolean, noNewKeyring: Boolean, preserveFds: Int,
        pidfdSocket: String?
    ): Int {
        if (State.exists(rootPath, containerId)) {
            System.err.println("container $containerId already exists")
            return 1
        }

        // Resolve bundle to an absolute path so later commands (start/delete) can
        // re-open config.json regardless of their cwd.
        val bundle: String
        try {
            bundle = Path.of(bundleIn).toAbsolutePath().normalize().toString()
        } catch (e: Exception) {
            System.err.println("invalid bundle path: ${e.message}")
            return 1
        }

        val spec: Spec
        try {
            spec = Json.readFile(Path.of(bundle, "config.json"), Spec::fromJson)!!
        } catch (e: java.nio.file.NoSuchFileException) {
            System.err.println("$bundle does not exist")
            return 1
        } catch (e: Exception) {
            System.err.println("failed to load config.json: ${e.message}")
            return 1
        }

        // OCI spec: the runtime MUST reject configs that contain invalid /
        // unsupported values. ociVersion must be a semver-like string. Anything
        // else (e.g. "invalid" — runtime-tools misc_props test) is rejected.
        if (spec.ociVersion == null
            || !spec.ociVersion.matches(Regex("""\d+\.\d+(\.\d+)?(-[\w.+-]+)?"""))) {
            System.err.println("invalid ociVersion: ${spec.ociVersion}")
            return 1
        }

        // runc compat: SCHED_DEADLINE cannot be used with CPU pinning.
        val scheduler = spec.process?.scheduler
        if (scheduler != null
            && scheduler.policy == "SCHED_DEADLINE"
            && spec.linux?.resources?.cpu?.cpus?.isNotEmpty() == true) {
            System.err.println("process scheduler can't be used together with AllowedCPUs")
            return 1
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

        val specRootPath = spec.root!!.path!!
        val rootfsPath = if (specRootPath.startsWith("/")) {
            specRootPath
        } else {
            "$bundle/$specRootPath"
        }
        Logger.debug("rootfs=$rootfsPath")

        val notifySocketPath = NotifySocket.pathFor(containerId)
        val notifyListenerFd = NotifySocket.createListener(notifySocketPath)

        val syncFds = IntArray(2)
        val mainFds = IntArray(2)
        Arena.ofConfined().use { arena ->
            if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, syncFds) < 0) {
                System.err.println("socketpair sync failed: ${Libc.strerror(Libc.errno())}")
                return 1
            }
            if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, mainFds) < 0) {
                System.err.println("socketpair main failed: ${Libc.strerror(Libc.errno())}")
                return 1
            }
        }
        val mainParentFd = mainFds[0]
        val mainChildFd = mainFds[1]

        val cloneFlags = NamespaceFlags.fromSpec(spec.linux?.namespaces)
        Logger.debug("clone flags=0x${Integer.toHexString(cloneFlags)}")

        // CVE-2019-5736 mitigation: seal /proc/self/exe so that a compromised
        // container cannot overwrite the host binary.  The sealed fd is passed
        // to the child as /proc/self/fd/N instead of the on-disk path.
        val sealedExeFd = ExeSeal.cloneSelfExe(rootPath)
        if (sealedExeFd < 0) {
            System.err.println("unable to create sealed /proc/self/exe clone (CVE-2019-5736)")
            return 1
        }
        val exePath = "/proc/self/fd/$sealedExeFd"

        val envList = HostEnv.inherited()
        envList.add("_TAKOYAKI_IS_BOOTSTRAP=1")
        envList.add("_TAKOYAKI_SYNCPIPE=${syncFds[1]}")
        envList.add("_TAKOYAKI_CLONE_FLAGS=${Integer.toHexString(cloneFlags)}")
        envList.add("_TAKOYAKI_MAIN_SENDER_FD=$mainChildFd")
        envList.add("_TAKOYAKI_NOTIFY_LISTENER_FD=$notifyListenerFd")
        envList.add("_TAKOYAKI_BUNDLE_PATH=$bundle")
        envList.add("_TAKOYAKI_ROOTFS_PATH=$rootfsPath")
        envList.add("_TAKOYAKI_CONTAINER_ID=$containerId")
        if (debug) envList.add("_TAKOYAKI_BOOTSTRAP_DEBUG=1")
        // Pass log configuration to the init process so it can redirect its
        // Logger output to the same file as the main process. Without this,
        // init's debug/warn output leaks to stderr (visible to bats tests).
        val logFilePath = Logger.logFilePath
        if (logFilePath != null) envList.add("_TAKOYAKI_LOG_FILE=$logFilePath")
        val logFmt = Logger.formatName
        if (logFmt != null) envList.add("_TAKOYAKI_LOG_FORMAT=$logFmt")
        // Pre-connect to the console socket on the HOST side so the init
        // process (which may run inside a user namespace as an unmapped uid)
        // doesn't need filesystem access to the socket path.  The connected
        // fd survives fork+execve (no CLOEXEC); InitProcess uses it directly.
        var consoleSocketFd = -1
        if (consoleSocket != null) {
            consoleSocketFd = ConsoleSocket.connectTo(consoleSocket)
            if (consoleSocketFd >= 0) {
                envList.add("_TAKOYAKI_CONSOLE_SOCKET_FD=$consoleSocketFd")
            } else {
                // Fall back to passing the path (non-userns case).
                envList.add("_TAKOYAKI_CONSOLE_SOCKET=$consoleSocket")
            }
        }
        if (noNewKeyring) envList.add("_TAKOYAKI_NO_NEW_KEYRING=1")
        if (noPivot) envList.add("_TAKOYAKI_NO_PIVOT=1")

        // Namespaces with an explicit `path` field: open the path on the host so
        // bootstrap.c can join via setns() instead of unshare(). The fd survives
        // fork+execve because we don't set CLOEXEC. Names match `setns` nstype
        // constants in bootstrap.c's switch table.
        val linuxNamespaces = spec.linux?.namespaces
        if (linuxNamespaces != null) {
            val nsFds = StringJoiner(",")
            Arena.ofConfined().use { openArena ->
                for (ns in linuxNamespaces) {
                    val nsPath = ns.path
                    if (nsPath.isNullOrEmpty()) continue
                    val fd = PosixIO.open(openArena, nsPath, Constants.O_RDONLY, 0)
                    if (fd < 0) {
                        System.err.println("open ns path ${ns.path} failed: ${Libc.strerror(Libc.errno())}")
                        return 1
                    }
                    nsFds.add("${ns.type}:$fd")
                }
            }
            if (nsFds.length() > 0) {
                envList.add("_TAKOYAKI_NS_FDS=$nsFds")
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
            val fdMap = StringJoiner(",")
            val usernsFdMap = StringJoiner(",")
            for (m in spec.mounts) {
                // Determine if this mount needs an idmap userns fd.
                // Explicit uidMappings on the mount take precedence; otherwise
                // the "idmap"/"ridmap" mount option with the container's userns
                // mappings (implied mapping).
                var uidMaps: List<Spec.IdMapping>? = m.uidMappings
                var gidMaps: List<Spec.IdMapping>? = m.gidMappings
                val hasExplicit = !uidMaps.isNullOrEmpty()
                var hasIdmapOption = false
                var isRidmap = false
                if (m.options != null) {
                    for (opt in m.options) {
                        if (opt == "idmap") {
                            hasIdmapOption = true
                        } else if (opt == "ridmap") {
                            hasIdmapOption = true
                            isRidmap = true
                        }
                    }
                }
                val linux = spec.linux
                if (!hasExplicit && hasIdmapOption && linux != null) {
                    uidMaps = linux.uidMappings
                    gidMaps = linux.gidMappings
                }

                // When joining an existing user namespace (userns path is set)
                // and no explicit mappings are available, use the joined userns's
                // fd directly for mount_setattr. Its uid_map/gid_map were already
                // set by whoever created it.
                var usernsFd = -1
                val idmapNsList = spec.linux?.namespaces
                if (uidMaps.isNullOrEmpty() && hasIdmapOption
                    && idmapNsList != null) {
                    for (ns in idmapNsList) {
                        val nsPathVal = ns.path
                        if (ns.type == "user" && !nsPathVal.isNullOrEmpty()) {
                            Arena.ofConfined().use { nsArena ->
                                usernsFd = PosixIO.open(nsArena, nsPathVal, Constants.O_RDONLY, 0)
                            }
                            if (usernsFd < 0) {
                                Logger.warn(
                                    "open joined userns ${ns.path}" +
                                        " for idmap failed: ${Libc.strerror(Libc.errno())}"
                                )
                            }
                            break
                        }
                    }
                }
                if (usernsFd < 0 && uidMaps.isNullOrEmpty()) continue

                // Step 1: create the helper userns with the desired uid/gid maps,
                // unless we already have a userns fd from joining an existing one.
                if (usernsFd < 0) {
                    usernsFd = IdmapHelper.setupHostSide(uidMaps!!, gidMaps ?: emptyList())
                }
                if (usernsFd < 0) {
                    Logger.warn(
                        "idmap helper setup failed for ${m.destination}" +
                            "; mount will fall back to plain bind"
                    )
                    continue
                }

                // Step 2: resolve the mount source to an absolute host path.
                var source = m.source
                if (!source.isNullOrEmpty()) {
                    val srcFile = java.io.File(source)
                    if (!srcFile.isAbsolute) {
                        source = srcFile.absolutePath
                    }
                }

                // Step 3: determine open_tree / mount_setattr flags from options.
                val parsed = MountOptions.parse(m.options)
                val cloneRecursive = (parsed.flags and Constants.MS_REC) != 0L
                val recursive = isRidmap || parsed.isRecursiveIdmap

                // Step 4: open_tree on the source, then apply MOUNT_ATTR_IDMAP.
                // Container-internal source: when the source path is within
                // the rootfs, its content may depend on earlier mounts in the
                // spec that haven't been applied yet on the host side. Defer
                // to the init process which can do open_tree after the
                // preceding mounts have been applied in order.
                val deferToInit = source != null
                    && (source.startsWith("$rootfsPath/") || source == rootfsPath)
                if (deferToInit) {
                    Logger.debug(
                        "source $source is inside rootfs for" +
                            " ${m.destination}; deferring idmap to init"
                    )
                    val ufl = PosixIO.fcntl(usernsFd, Constants.F_GETFD, 0)
                    if (ufl >= 0) {
                        PosixIO.fcntl(usernsFd, Constants.F_SETFD, ufl and Constants.FD_CLOEXEC.inv())
                    }
                    usernsFdMap.add(
                        "${Base64.getEncoder().encodeToString(m.destination!!.toByteArray())}:$usernsFd" +
                            ":${if (recursive) 1 else 0}"
                    )
                    continue
                }
                val treeFd = IdmapMount.openTree(source!!, cloneRecursive)
                if (treeFd < 0) {
                    Logger.warn(
                        "open_tree($source) failed for ${m.destination}" +
                            "; mount will fall back to plain bind"
                    )
                    PosixIO.close(usernsFd)
                    continue
                }
                // open_tree sets CLOEXEC by default. Clear it so the fd
                // survives fork+execve into bootstrap.c -> Java init.
                val fl = PosixIO.fcntl(treeFd, Constants.F_GETFD, 0)
                if (fl >= 0) {
                    PosixIO.fcntl(treeFd, Constants.F_SETFD, fl and Constants.FD_CLOEXEC.inv())
                }
                if (!IdmapMount.setIdmap(treeFd, usernsFd, recursive)) {
                    Logger.warn(
                        "mount_setattr(IDMAP) failed for ${m.destination}" +
                            "; mount will fall back to plain bind"
                    )
                    PosixIO.close(treeFd)
                    PosixIO.close(usernsFd)
                    continue
                }
                PosixIO.close(usernsFd)

                fdMap.add(
                    "${Base64.getEncoder().encodeToString(m.destination!!.toByteArray())}:$treeFd"
                )
            }
            if (fdMap.length() > 0) {
                envList.add("_TAKOYAKI_IDMAP_FDS=$fdMap")
            }
            if (usernsFdMap.length() > 0) {
                envList.add("_TAKOYAKI_IDMAP_USERNS_FDS=$usernsFdMap")
            }
        }

        // Bind mount source fds: when a user namespace is configured, bind
        // mount sources that are inaccessible to the mapped container UID
        // must be pre-opened on the host side (as root in init_user_ns).
        // We use open_tree(OPEN_TREE_CLONE) to create a detached mount tree
        // fd, which the init process can later attach via move_mount().
        // This avoids the EINVAL that mount(2) returns when resolving
        // /proc/self/fd/N through inaccessible intermediate directories.
        val hasUserns = (cloneFlags and Constants.CLONE_NEWUSER) != 0
            || spec.hasNamespace("user")
        if (hasUserns && spec.mounts != null) {
            val bindFdMap = StringJoiner(",")
            Arena.ofConfined().use { bindArena ->
                for (m in spec.mounts) {
                    if (m.source.isNullOrEmpty()) continue
                    var isBind = false
                    var isRbind = false
                    if (m.options != null) {
                        for (opt in m.options) {
                            if (opt == "bind") isBind = true
                            if (opt == "rbind") { isBind = true; isRbind = true }
                        }
                    }
                    if (!isBind) continue

                    var absSource = m.source!!
                    if (!java.io.File(absSource).isAbsolute) {
                        absSource = java.io.File(absSource).absolutePath
                    }

                    if (PosixIO.access(bindArena, absSource, Constants.F_OK) != 0) {
                        continue
                    }

                    // Only pre-open sources that would become inaccessible
                    // inside the user namespace. Check each intermediate
                    // directory for others-execute (o+x) permission. If all
                    // components are world-traversable, the regular mount
                    // path will work fine and pre-opening would be wrong for
                    // container-internal sources (earlier mounts in the spec
                    // that shadow the host path).
                    var needsPreOpen = false
                    val srcPath = Path.of(absSource)
                    var dir = srcPath.parent
                    while (dir != null && dir.toString() != "/") {
                        if (!java.nio.file.Files.exists(dir)) break
                        try {
                            val mode = (java.nio.file.Files.getAttribute(dir, "unix:mode") as Int) and 0xFFF // 07777
                            if ((mode and 1) == 0) {
                                needsPreOpen = true
                                break
                            }
                        } catch (_: Exception) {
                            break
                        }
                        dir = dir.parent
                    }
                    if (!needsPreOpen) continue

                    val srcFd = IdmapMount.openTree(absSource, isRbind)
                    if (srcFd < 0) {
                        Logger.warn(
                            "open_tree $absSource failed; " +
                                "bind mount will be attempted directly"
                        )
                        continue
                    }
                    // open_tree sets CLOEXEC by default. Clear it so the fd
                    // survives fork+execve into bootstrap.c -> Java init.
                    val fl = PosixIO.fcntl(srcFd, Constants.F_GETFD, 0)
                    if (fl >= 0) {
                        PosixIO.fcntl(srcFd, Constants.F_SETFD, fl and Constants.FD_CLOEXEC.inv())
                    }
                    bindFdMap.add(
                        "${Base64.getEncoder().encodeToString(m.destination!!.toByteArray())}:$srcFd"
                    )
                    Logger.debug(
                        "open_tree bind source $absSource as fd $srcFd for ${m.destination}"
                    )
                }
            }
            if (bindFdMap.length() > 0) {
                envList.add("_TAKOYAKI_BIND_SOURCE_FDS=$bindFdMap")
            }
        }

        // Seccomp notify listener: connect on the host side (where the listener
        // socket path actually resolves) and pass the connected fd to the init via
        // env. After the init pivots into the container rootfs the listener path is
        // no longer reachable, so this has to happen here.
        val seccomp = spec.linux?.seccomp
        if (seccomp != null) {
            val hasNotify = seccomp.hasNotifyAction()
            val listenerPath = seccomp.listenerPath
            if (hasNotify && listenerPath.isNullOrEmpty()) {
                System.err.println("seccomp listenerPath is not set")
                return 1
            }
            if (!listenerPath.isNullOrEmpty()) {
                val fd = SeccompListener.connectHostSide(listenerPath)
                if (fd >= 0) {
                    envList.add("_TAKOYAKI_SECCOMP_LISTENER_FD=$fd")
                } else {
                    System.err.println(
                        "failed to connect with seccomp agent specified in the seccomp profile: " +
                            listenerPath
                    )
                    return 1
                }
            }
        }

        // timens offsets must be written in stage-1 of bootstrap.c BEFORE execve into
        // Java. The kernel rejects /proc/self/timens_offsets writes after exec, so the
        // Java side can never do it. Pass the offsets through env vars instead.
        val timeOffsets = spec.linux?.timeOffsets
        if (timeOffsets != null) {
            val bt = timeOffsets["boottime"]
            if (bt != null) {
                envList.add("_TAKOYAKI_TIMENS_BOOTTIME_SECS=${bt.secs}")
                envList.add("_TAKOYAKI_TIMENS_BOOTTIME_NSEC=${bt.nanosecs}")
            }
            val mt = timeOffsets["monotonic"]
            if (mt != null) {
                envList.add("_TAKOYAKI_TIMENS_MONOTONIC_SECS=${mt.secs}")
                envList.add("_TAKOYAKI_TIMENS_MONOTONIC_NSEC=${mt.nanosecs}")
            }
        }
        val envp = envList.toTypedArray()
        val argv = arrayOf(exePath, "__init__")

        val execArena = Arena.ofShared()
        val payload = PosixIO.ExecvePayload.build(execArena, exePath, argv, envp)

        val forkPid = PosixIO.fork()
        if (forkPid < 0) {
            System.err.println("fork failed: ${Libc.strerror(Libc.errno())}")
            return 1
        }
        if (forkPid == 0) {
            PosixIO.close(syncFds[0])
            PosixIO.close(mainParentFd)
            PosixIO.invokeExecve(payload)
            PosixIO._exit(1)
            return 1
        }

        PosixIO.close(syncFds[1])
        PosixIO.close(mainChildFd)

        MainProcess.run(
            forkPid, syncFds[0], spec, containerId,
            bundle, rootPath, pidFile, notifyListenerFd, mainParentFd,
            pidfdSocket
        )
        return 0
    }
}
