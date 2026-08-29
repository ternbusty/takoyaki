package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.console.ConsoleSocket
import java.io.IOException
import com.ternbusty.takoyaki.hooks.Hooks
import com.ternbusty.takoyaki.ipc.NotifySocket
import com.ternbusty.takoyaki.ipc.SyncChannel
import com.ternbusty.takoyaki.keyring.Keyring
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.network.Loopback
import com.ternbusty.takoyaki.rootfs.Devices
import com.ternbusty.takoyaki.rootfs.Rootfs
import com.ternbusty.takoyaki.rootfs.UserDb
import com.ternbusty.takoyaki.selinux.SeLinux
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.CloseRange
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.sysctl.Sysctl
import com.ternbusty.takoyaki.util.JsonCodec
import java.lang.foreign.Arena
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

object InitProcess {

    /**
     * Build the transient [State] object that gets piped to hooks running
     * inside the container namespace (createContainer / startContainer).
     *
     * The persisted state.json is written by MainProcess after INIT_READY, so it
     * does not exist yet when these hooks fire. Rebuild an equivalent structure
     * here from what the init already knows: spec + env-vars + own pid.
     */
    internal fun buildState(
        spec: Spec,
        containerId: String,
        bundlePath: String,
        status: ContainerStatus
    ): State = State.create(
        spec.ociVersion,
        containerId,
        status,
        Libc.getpid(),
        bundlePath,
        spec.annotations
    )

    /**
     * Parse the `_TAKOYAKI_IDMAP_FDS` env value into a destination-path
     * -> fd map.
     *
     * Wire format: `base64(destPath1):fd1,base64(destPath2):fd2,...`
     * Base64 because destination paths can contain '=' or ',' which are the
     * separators. Malformed entries (missing colon, bogus base64) are silently
     * skipped -- the init must still come up.
     *
     * Package-visible for unit tests.
     */
    internal fun parseIdmapFds(env: String?): MutableMap<String, Int> {
        val out = LinkedHashMap<String, Int>()
        if (env.isNullOrEmpty()) return out
        for (entry in env.split(",")) {
            val colon = entry.indexOf(':')
            if (colon < 0) continue
            try {
                val dest = String(Base64.getDecoder().decode(entry.substring(0, colon)))
                val fd = entry.substring(colon + 1).toInt()
                out[dest] = fd
            } catch (_: IllegalArgumentException) {
                // bad base64 or non-numeric fd; skip
            }
        }
        return out
    }

    /**
     * Parse deferred idmap userns fds from _TAKOYAKI_IDMAP_USERNS_FDS.
     * Format: base64(dest):usernsFd:recursive,...
     * Returns map from destination to [usernsFd, recursive].
     */
    internal fun parseDeferredIdmapFds(env: String?): MutableMap<String, IntArray> {
        val out = LinkedHashMap<String, IntArray>()
        if (env.isNullOrEmpty()) return out
        for (entry in env.split(",")) {
            val parts = entry.split(":")
            if (parts.size < 3) continue
            try {
                val dest = String(Base64.getDecoder().decode(parts[0]))
                val fd = parts[1].toInt()
                val recursive = parts[2].toInt()
                out[dest] = intArrayOf(fd, recursive)
            } catch (_: IllegalArgumentException) {
                // bad base64 or non-numeric; skip
            }
        }
        return out
    }

    /**
     * Parse pre-opened bind mount source fds from _TAKOYAKI_BIND_SOURCE_FDS.
     * Format: base64(dest):fd,...
     * Returns map from destination to fd.
     */
    internal fun parseBindSourceFds(env: String?): MutableMap<String, Int> {
        val out = LinkedHashMap<String, Int>()
        if (env.isNullOrEmpty()) return out
        for (entry in env.split(",")) {
            val parts = entry.split(":")
            if (parts.size < 2) continue
            try {
                val dest = String(Base64.getDecoder().decode(parts[0]))
                val fd = parts[1].toInt()
                out[dest] = fd
            } catch (_: IllegalArgumentException) {
                // bad base64 or non-numeric; skip
            }
        }
        return out
    }

    fun run() {
        Logger.context = "init"
        // Inherit log configuration from the main process so that debug/warn
        // output goes to the log file instead of leaking to stderr. Must be
        // configured BEFORE any Logger call.
        System.getenv("_TAKOYAKI_LOG_FILE")?.let { Logger.setLogFile(it) }
        val initLogFormat = System.getenv("_TAKOYAKI_LOG_FORMAT")
        if ("json".equals(initLogFormat, ignoreCase = true)) {
            Logger.format = Logger.Format.JSON
        }
        Logger.debug("init started, pid=${Libc.getpid()} ppid=${Libc.getppid()}")
        if (Logger.isDebugEnabled) {
            try {
                val mntNs = Files.readSymbolicLink(Path.of("/proc/self/ns/mnt")).toString()
                val pidNs = Files.readSymbolicLink(Path.of("/proc/self/ns/pid")).toString()
                Logger.debug("init mnt_ns=$mntNs pid_ns=$pidNs")
            } catch (e: Exception) {
                Logger.warn("could not read ns: ${e.message}")
            }
        }

        val bundlePath = System.getenv("_TAKOYAKI_BUNDLE_PATH")
        val rootfsPath = System.getenv("_TAKOYAKI_ROOTFS_PATH")
        val mainSenderFdStr = System.getenv("_TAKOYAKI_MAIN_SENDER_FD")
        val notifyListenerFdStr = System.getenv("_TAKOYAKI_NOTIFY_LISTENER_FD")

        if (bundlePath == null || rootfsPath == null || mainSenderFdStr == null
            || notifyListenerFdStr == null
        ) {
            Logger.error("missing required env vars")
            PosixIO._exit(1)
            return
        }

        val mainSenderFd = mainSenderFdStr.toInt()
        val notifyListenerFd = notifyListenerFdStr.toInt()

        // Optional: host-side pre-connected seccomp listener socket, prepared by
        // CreateCommand when the spec has a seccomp listenerPath. -1 when absent.
        val seccompListenerFd = System.getenv("_TAKOYAKI_SECCOMP_LISTENER_FD")?.toInt() ?: -1

        val spec: Spec
        try {
            spec = JsonCodec.loadFromFile<Spec>(Path.of(bundlePath, "config.json"))
                ?: throw IOException("failed to parse spec from $bundlePath/config.json")
        } catch (e: Exception) {
            Logger.error("failed to load spec: ${e.message}")
            PosixIO._exit(1)
            return
        }

        try {
            Arena.ofConfined().use { arena ->
                // libseccomp.so.2 is linked at NEEDED so ld.so loads it at process startup,
                // before pivot_root replaces the rootfs. No explicit preload required.

                // Become subreaper so orphaned descendants are reaped by this init
                // (PID 1 inside the container's pid namespace).
                if (Libc.prctl(Constants.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
                    Logger.debug("PR_SET_CHILD_SUBREAPER failed: ${Libc.strerror(Libc.errno())}")
                }

                // timens offsets are applied in bootstrap.c stage-1 (before execve into
                // the Java init), because /proc/self/timens_offsets is no longer writable
                // after exec or after gettimeofday is called. The Java init cannot do it.

                // Apply process.oomScoreAdj. Writes to /proc/self/oom_score_adj so it
                // is inherited by the user process after exec.
                spec.process?.let { p ->
                    ProcessRestrictions.applyOomScoreAdj(p.oomScoreAdj)
                }

                // Parse pre-prepared idmap helper fds passed via env from CreateCommand.
                // Keys are base64-encoded destination paths; values are fd numbers
                // referring to /proc/<helper>/ns/user opened in the host pid/user ns,
                // inherited across fork+execve.
                val idmapFds = parseIdmapFds(System.getenv("_TAKOYAKI_IDMAP_FDS"))
                for ((key, value) in idmapFds) {
                    Logger.debug("idmap fd inherited: $key -> $value")
                }

                // Pre-opened bind mount source fds: when a user namespace is in use,
                // the host opened bind mount sources that would be inaccessible to
                // the mapped container uid. The init uses /proc/self/fd/N as source.
                val bindSourceFds = parseBindSourceFds(System.getenv("_TAKOYAKI_BIND_SOURCE_FDS"))
                for ((key, value) in bindSourceFds) {
                    Logger.debug("bind source fd inherited: $key -> fd=$value")
                }

                // Deferred idmap userns fds: for container-internal sources where
                // open_tree failed on the host (source depends on earlier mounts),
                // the host created the userns fd but skipped open_tree + mount_setattr.
                // The init does open_tree locally (after earlier mounts are applied)
                // then mount_setattr + move_mount.
                // Format: base64(dest):usernsFd:recursive,...
                val idmapUsernsFds =
                    parseDeferredIdmapFds(System.getenv("_TAKOYAKI_IDMAP_USERNS_FDS"))
                for ((key, value) in idmapUsernsFds) {
                    Logger.debug("deferred idmap userns fd: $key -> fd=${value[0]} recursive=${value[1]}")
                }

                val containerId = System.getenv("_TAKOYAKI_CONTAINER_ID")

                // Console socket: prefer the pre-connected fd from CreateCommand
                // (which connects on the host side, before entering any userns).
                // Fall back to connecting via path for the non-userns case or when
                // the CLI couldn't pre-connect.
                val wantTerminal = spec.process?.terminal == true
                var consoleSocketFd = -1
                if (wantTerminal) {
                    val preConnectedFd = System.getenv("_TAKOYAKI_CONSOLE_SOCKET_FD")
                    if (preConnectedFd != null) {
                        consoleSocketFd = preConnectedFd.toInt()
                        Logger.debug("using pre-connected console socket fd $consoleSocketFd")
                    } else {
                        val consoleSocketPath = System.getenv("_TAKOYAKI_CONSOLE_SOCKET")
                        if (consoleSocketPath != null) {
                            consoleSocketFd = ConsoleSocket.connectTo(consoleSocketPath)
                            if (consoleSocketFd < 0) {
                                Logger.warn("failed to connect to console socket $consoleSocketPath")
                            }
                        }
                    }
                }

                if (spec.hasNamespace("mount")) {
                    Rootfs.prepare(rootfsPath, spec, idmapFds, idmapUsernsFds, bindSourceFds)
                    // Additional devices declared in spec.linux.devices, before pivot_root.
                    val linuxDevices = spec.linux?.devices
                    if (linuxDevices != null) {
                        Devices.create(rootfsPath, linuxDevices)
                    }
                    // createContainer hooks run in the container namespace after the
                    // rootfs is fully assembled but before pivot_root. Per the OCI
                    // runtime spec, hooks that fail (non-zero exit or timeout) MUST
                    // abort container creation -- runFailFast throws which the outer
                    // catch converts into _exit(1).
                    val createContainerHooks = spec.hooks?.createContainer
                    if (createContainerHooks != null && containerId != null) {
                        Hooks.runFailFast(
                            createContainerHooks,
                            buildState(spec, containerId, bundlePath, ContainerStatus.CREATING),
                            "createContainer"
                        )
                    }
                    val noPivot = "1" == System.getenv("_TAKOYAKI_NO_PIVOT")
                    if (noPivot) {
                        Rootfs.msMoveRoot(rootfsPath, spec.linux?.rootfsPropagation)
                    } else {
                        Rootfs.pivot(rootfsPath, spec.linux?.rootfsPropagation)
                    }
                } else {
                    Logger.debug("no mount namespace, skipping rootfs prep")
                }

                // Bring up loopback so localhost works inside the network namespace.
                // Rename network devices that were moved into this namespace by
                // MainProcess before loopback comes up.
                if (spec.hasNamespace("network")) {
                    spec.linux?.netDevices?.let { nd ->
                        if (nd.isNotEmpty()) {
                            com.ternbusty.takoyaki.network.NetDevice.renameDevices(nd)
                        }
                    }
                    Loopback.up()
                }

                // Apply spec.linux.sysctl after mounts are in place (so /proc/sys is visible).
                val linuxSysctl = spec.linux?.sysctl
                if (linuxSysctl != null) {
                    Sysctl.apply(linuxSysctl)
                }

                val cwd = spec.process?.cwd ?: "/"
                if (Libc.chdir(arena, cwd) != 0) {
                    Logger.warn("chdir $cwd failed: ${Libc.strerror(Libc.errno())}")
                }

                val specHostname = spec.hostname
                if (specHostname != null) {
                    if (Libc.sethostname(arena, specHostname) != 0) {
                        Logger.warn("sethostname failed: ${Libc.strerror(Libc.errno())}")
                    } else {
                        Logger.debug("hostname set to $specHostname")
                    }
                }

                val specDomainname = spec.domainname
                if (!specDomainname.isNullOrEmpty()) {
                    if (Libc.setdomainname(arena, specDomainname) != 0) {
                        Logger.warn("setdomainname failed: ${Libc.strerror(Libc.errno())}")
                    } else {
                        Logger.debug("domainname set to $specDomainname")
                    }
                }

                // Mask sensitive paths and remount others read-only BEFORE the root is made RO,
                // so the bind / remount itself can still succeed.
                val specLinuxPaths = spec.linux
                if (specLinuxPaths != null) {
                    Rootfs.maskPaths(specLinuxPaths.maskedPaths)
                    Rootfs.readonlyRemount(specLinuxPaths.readonlyPaths)
                }

                // Generate /etc/passwd and /etc/group entries while still writable.
                spec.process?.let { p ->
                    UserDb.ensure(p.user)
                }

                val specRoot = spec.root
                if (specRoot != null && specRoot.readonly) {
                    Rootfs.setRootReadonly()
                }

                // Join a fresh kernel session keyring unless the caller opted out via
                // --no-new-keyring (we propagate that via env var). Must happen before
                // the restriction sequence so no seccomp filter can veto keyctl.
                //
                // When a SELinux label is configured, write it to
                // /proc/self/attr/keycreate BEFORE creating the keyring so the
                // kernel stamps the correct label on the new key. Without this
                // the keyring inherits the runtime's label and the container
                // process (running under container_t) cannot access it.
                // Clear keycreate afterwards so subsequent key operations do not
                // inherit the override.
                if ("1" != System.getenv("_TAKOYAKI_NO_NEW_KEYRING")) {
                    val seLabel = spec.process?.selinuxLabel
                    SeLinux.applyKeyCreate(seLabel)
                    Keyring.joinNewSession("_ses.$containerId")
                    SeLinux.clearKeyCreate()
                }

                // Default umask 0022 for the init path (runc compat). The
                // restriction sequence may override it from the spec.
                Libc.umask(0x12) // 0022 octal

                // I/O priority and scheduler must be applied while still
                // fully privileged, before the restriction sequence drops caps.
                spec.process?.let { p ->
                    ProcessRestrictions.applyIOPriority(p.ioPriority)
                    ProcessRestrictions.applyScheduler(p.scheduler)
                }

                // NUMA memory policy (linux.memoryPolicy): applied before cap drop
                // and inherited by execve.
                spec.linux?.let { linux ->
                    MemPolicy.apply(linux.memoryPolicy)
                }

                // Apply rlimits BEFORE dropping capabilities (ProcessRestrictions.apply).
                // Setting RLIMIT_NOFILE above fs.nr_open requires CAP_SYS_RESOURCE,
                // which is gone after cap drop. RLIMIT_AS is deferred to just before
                // execve to avoid OOMing the JVM's heap.
                val procRlimits = spec.process?.rlimits
                if (procRlimits != null) {
                    com.ternbusty.takoyaki.syscall.Rlimit.applyExcept(
                        Libc.getpid(), procRlimits, "RLIMIT_AS"
                    )
                }

                val cid = containerId ?: ""
                ProcessRestrictions.apply(
                    spec.process,
                    spec.linux?.seccomp,
                    buildState(spec, cid, bundlePath, ContainerStatus.CREATED),
                    seccompListenerFd
                )

                // PTY setup: if process.terminal is true and the console socket was
                // pre-connected (before pivot_root), open a pty from the container's
                // devpts, ship the master to the console socket, and wire stdio to
                // the slave. The new session leadership has to happen before wiring so
                // the slave can become the controlling terminal of this process.
                var ptySlave = -1
                if (consoleSocketFd >= 0) {
                    val pty = ConsoleSocket.openPty()
                    if (pty != null) {
                        if (!ConsoleSocket.sendMasterVia(consoleSocketFd, pty.master)) {
                            Logger.warn("failed to ship pty master, falling back to no-tty")
                        } else {
                            ptySlave = pty.slave
                        }
                        PosixIO.close(pty.master)
                    }
                    PosixIO.close(consoleSocketFd)
                }

                Logger.debug("init: closing the pipe to signal completion")
                SyncChannel.writeInt32(mainSenderFd, SyncChannel.MSG_INIT_READY)
                PosixIO.close(mainSenderFd)

                if (ptySlave >= 0) {
                    val consoleSize = spec.process?.consoleSize
                    if (consoleSize != null) {
                        ConsoleSocket.setWinsize(
                            ptySlave,
                            consoleSize.height.toInt(),
                            consoleSize.width.toInt()
                        )
                    }
                    ConsoleSocket.wireStdio(ptySlave)
                }

                // Close all fds >= 3 except notifyListenerFd. Using actual close
                // (not just CLOEXEC) so the fd leak test does not see stray fds
                // during the "created" wait. After this, only stdio and the
                // notify socket remain open.
                CloseRange.closeAllExcept(notifyListenerFd)

                Logger.debug("waiting for start signal on notify fd $notifyListenerFd")
                NotifySocket.waitForStart(notifyListenerFd)
                PosixIO.close(notifyListenerFd)

                val process = spec.process
                if (process == null || process.args.isNullOrEmpty()) {
                    Logger.error("process.args is empty")
                    PosixIO._exit(1)
                    return
                }

                // Prepare the environment: dedup (last wins), inject HOME if empty.
                val envMap = LinkedHashMap<String, String>()
                process.env?.forEach { entry ->
                    val eq = entry.indexOf('=')
                    if (eq > 0) {
                        envMap[entry.substring(0, eq)] = entry.substring(eq + 1)
                    }
                }
                // runc behaviour (env.go prepareEnv): if HOME is empty or absent
                // after dedup, look up the user's home in /etc/passwd and set it.
                // Non-empty HOME is kept as-is.
                val homeVal = envMap["HOME"]
                if (homeVal.isNullOrEmpty()) {
                    val uid = process.user?.uid ?: 0u
                    val passwdHome = UserDb.lookupHome(uid.toInt())
                    if (!passwdHome.isNullOrEmpty()) {
                        envMap["HOME"] = passwdHome
                    } else {
                        envMap["HOME"] = "/"
                    }
                }

                Libc.clearenv()
                for ((key, value) in envMap) {
                    Libc.setenv(arena, key, value, true)
                }

                val argv = process.args.toTypedArray()
                Logger.info("executing: ${argv.joinToString(" ")}")

                // Apply RLIMIT_AS LAST -- after the JVM has done all its heap
                // and address-space provisioning. If we did this earlier, a low
                // RLIMIT_AS (e.g. 1 GiB) would push the JVM's already-mapped heap
                // over the limit and the very next allocation would OOM. The
                // about-to-execve user process picks up the new limits.
                // Other rlimits were already applied above (before cap drop).
                process.rlimits?.let { rlimits ->
                    com.ternbusty.takoyaki.syscall.Rlimit.applyOnly(
                        Libc.getpid(), rlimits, "RLIMIT_AS"
                    )
                }

                // startContainer hooks: last chance for the runtime to poke around
                // in the fully-set-up container namespace before handing control to
                // the user process. Per OCI, failable -- non-zero exit aborts start.
                // runc's startContainer hooks inherit the process environment when
                // the hook itself does not specify an env field.
                val startContainerHooks = spec.hooks?.startContainer
                if (startContainerHooks != null && containerId != null) {
                    // Build the env list that the process will get (after dedup +
                    // HOME injection) so the hook sees the same environment.
                    val hookEnv = envMap.entries.map { (k, v) -> "$k=$v" }
                    Hooks.runFailFast(
                        startContainerHooks,
                        buildState(spec, containerId, bundlePath, ContainerStatus.CREATED),
                        "startContainer", hookEnv
                    )
                }

                // Re-apply CLOEXEC on all FDs >= 3. The first closeAllAbove(0)
                // ran earlier, but Java code between then and now may have opened
                // new FDs (e.g. Files.readString for /etc/passwd, FFM library
                // handles, hook fork/exec). This second pass catches any late
                // arrivals right before execvp closes them.
                CloseRange.closeAllAbove(0)

                Libc.execvp(arena, argv[0], argv)
                // runc-compatible error message: plain text to stderr regardless
                // of Logger level, so bats tests can assert on it.
                // Go's syscall.Errno.Error() returns lowercase; C's strerror
                // returns uppercase. Lowercase the first char to match runc.
                val rawErr = Libc.strerror(Libc.errno())
                val errMsg = if (rawErr.isEmpty()) rawErr
                else rawErr[0].lowercaseChar() + rawErr.substring(1)
                // Distinguish "binary not found" from "exec failed" (e.g. bad
                // shebang). When the binary itself does not exist, runc wraps it
                // as a container-process error; when exec itself fails (file
                // exists but can't be run), it prints the bare exec error.
                val binaryExists = java.io.File(argv[0]).exists()
                if (!binaryExists) {
                    System.err.println("exec container process caused: exec ${argv[0]}: $errMsg")
                } else {
                    System.err.println("exec ${argv[0]}: $errMsg")
                }
                PosixIO._exit(1)
            }
        } catch (e: Exception) {
            // Print user-facing error to stderr (runc compat). Logger alone
            // is silent at the default level, and bats tests assert on the
            // message in $output.
            val msg = e.message
            if (msg != null) {
                System.err.println(msg)
            }
            Logger.error("init failed: $msg")
            PosixIO._exit(1)
        }
    }
}
