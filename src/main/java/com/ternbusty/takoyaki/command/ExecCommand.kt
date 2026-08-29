package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.console.ConsoleSocket
import com.ternbusty.takoyaki.console.InternalConsole
import com.ternbusty.takoyaki.console.PidfdSocket
import com.ternbusty.takoyaki.ipc.SyncChannel
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.process.ExecPayload
import com.ternbusty.takoyaki.seccomp.SeccompListener
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.util.JsonCodec
import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path

/**
 * Run an additional command inside an existing container. Equivalent to
 * `runc exec`: the new process gets the container's namespaces AND the full
 * restriction set (cgroup membership, seccomp, capabilities, AppArmor/SELinux
 * label, no_new_privs, rlimits) re-applied, since none of those are inherited
 * through setns alone.
 *
 * Host-side half: resolves the effective process document and everything else
 * that needs host paths (config.json, cgroup path, seccomp listener socket,
 * /proc/<init>/ns fds), then forks and re-execs /proc/self/exe __exec__
 * while still in the host namespaces (see ExecProcess for why the re-exec
 * must precede setns). The payload travels over a socketpair.
 */
object ExecCommand {

    /** Namespaces to join, in application order (see ExecProcess). */
    private val NS_ORDER = arrayOf("user", "cgroup", "ipc", "uts", "net", "time", "pid", "mnt")

    /** runc-compatible exit code for runtime-level exec errors. */
    private const val EXIT_RUNTIME_ERROR = 255

    @Suppress("LongParameterList")
    fun run(
        rootPath: String, containerId: String, processJsonPath: String?,
        user: String?, cwd: String?, envs: List<String>?, command: List<String>?,
        detach: Boolean, pidFile: String?, tty: Boolean, consoleSocket: String?,
        additionalGids: List<String>?, caps: List<String>?, preserveFds: Int,
        subCgroupPath: String?, consoleSize: ConsoleSize?, ignorePaused: Boolean,
        pidfdSocket: String?
    ): Int {
        val exclusivity = exclusivityError(processJsonPath, user, cwd, envs, command)
        if (exclusivity != null) {
            System.err.println(exclusivity)
            return EXIT_RUNTIME_ERROR
        }

        var state: State
        try {
            state = State.load(rootPath, containerId).refreshStatus()
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            return EXIT_RUNTIME_ERROR
        }
        if (state.statusEnum() == ContainerStatus.PAUSED) {
            if (!ignorePaused) {
                System.err.println("cannot exec in a paused container")
                return EXIT_RUNTIME_ERROR
            }
            // --ignore-paused: poll cgroup.freeze until the container is resumed.
            val cgroupPathForFreeze: String? = try {
                KontainerConfig.load(rootPath, containerId).cgroupPath
            } catch (e: Exception) {
                System.err.println("cannot read cgroup config for $containerId")
                return EXIT_RUNTIME_ERROR
            }
            if (cgroupPathForFreeze != null) {
                val freezePath = Cgroup.dir(cgroupPathForFreeze).resolve("cgroup.freeze")
                while (true) {
                    try {
                        val v = Files.readString(freezePath).trim()
                        if (v == "0") break
                    } catch (e: IOException) {
                        break
                    }
                    try {
                        Thread.sleep(100)
                    } catch (e: InterruptedException) {
                        break
                    }
                }
            }
            // Re-read state after waiting for resume.
            try {
                state = State.load(rootPath, containerId).refreshStatus()
            } catch (e: Exception) {
                System.err.println("container $containerId does not exist")
                return EXIT_RUNTIME_ERROR
            }
        }

        val initPid = state.pid
        if ((state.statusEnum() != ContainerStatus.RUNNING
                    && state.statusEnum() != ContainerStatus.CREATED)
            || initPid == null
        ) {
            System.err.println("container $containerId is not running")
            return EXIT_RUNTIME_ERROR
        }

        val spec: Spec = try {
            JsonCodec.loadFromFile<Spec>(Path.of(state.bundle, "config.json"))
        } catch (e: Exception) {
            System.err.println("failed to load config.json: ${e.message}")
            return EXIT_RUNTIME_ERROR
        }

        // Effective process document: `-p FILE` verbatim (runc semantics), or
        // the container's own process section with CLI overrides applied.
        var process: Process = try {
            if (processJsonPath != null) {
                val p = JsonCodec.loadFromFile<Process>(Path.of(processJsonPath))
                if (p.args.isEmpty()) {
                    System.err.println("process.json has no args")
                    return EXIT_RUNTIME_ERROR
                }
                p
            } else {
                buildEffectiveProcess(
                    spec.process, user, cwd, envs, command,
                    tty, additionalGids, caps
                )
            }
        } catch (e: Exception) {
            System.err.println("failed to build process document: ${e.message}")
            return EXIT_RUNTIME_ERROR
        }

        // Apply --console-size if provided by the CLI.
        if (consoleSize != null) {
            process = process.copy(consoleSize = consoleSize)
        }

        // Resolve effective execCPUAffinity: process.json overrides config.json.
        val effectiveAffinity = process.execCPUAffinity ?: spec.process?.execCPUAffinity

        // A missing runtime config just means a container created before cgroup
        // support (skip); any other load failure must NOT silently exec the
        // process outside the container's resource limits.
        var cgroupPath: String? = null
        var noNewKeyring = false
        try {
            val kc = KontainerConfig.load(rootPath, containerId)
            cgroupPath = kc.cgroupPath
            noNewKeyring = kc.noNewKeyring
        } catch (e: NoSuchFileException) {
            Logger.debug("no cgroup config for $containerId")
        } catch (e: Exception) {
            System.err.println("failed to load cgroup config: ${e.message}")
            return EXIT_RUNTIME_ERROR
        }

        val payload = ExecPayload(
            containerId = containerId,
            bundle = state.bundle,
            ociVersion = state.ociVersion,
            process = process,
            seccomp = spec.linux?.seccomp,
            memoryPolicy = spec.linux?.memoryPolicy,
            preserveFds = preserveFds,
            noNewKeyring = noNewKeyring,
        )

        // runc compat: --cgroup PATH resolves to a subcgroup under the
        // container's cgroup. "/" means the container root cgroup (default).
        // A non-existing subcgroup is an error.
        var effectiveCgroupPath = cgroupPath
        var cgroupExplicitRoot = false
        if (subCgroupPath != null && subCgroupPath != "/") {
            if (cgroupPath == null) {
                System.err.println("--cgroup specified but container has no cgroup")
                return EXIT_RUNTIME_ERROR
            }
            val resolved = "$cgroupPath/$subCgroupPath"
            if (!Files.isDirectory(Cgroup.dir(resolved))) {
                System.err.println("exec cgroup $resolved: no such file or directory")
                return EXIT_RUNTIME_ERROR
            }
            effectiveCgroupPath = resolved
        }
        if (subCgroupPath == "/") {
            cgroupExplicitRoot = true
        }

        Arena.ofConfined().use { arena ->
            return spawn(
                arena, initPid, payload, effectiveCgroupPath, detach,
                pidFile, effectiveAffinity, cgroupExplicitRoot, cgroupPath,
                consoleSocket, pidfdSocket
            )
        }
    }

    /**
     * `-p` hands over the whole process document, so combining it with the
     * flag-level overrides is ambiguous; runc resolves this by ignoring the
     * flags, we reject them outright. Returns an error message, or null when
     * the combination is fine. Internal for unit tests.
     */
    internal fun exclusivityError(
        processJsonPath: String?, user: String?, cwd: String?,
        envs: List<String>?, command: List<String>?
    ): String? {
        if (processJsonPath == null) return null
        if (user != null || cwd != null
            || (!envs.isNullOrEmpty())
            || (!command.isNullOrEmpty())
        ) {
            return "--process cannot be combined with -u/--cwd/-e or a command"
        }
        return null
    }

    /**
     * The container's process section with exec CLI overrides applied on top:
     * positional command replaces args, -u replaces uid/gid (keeping the
     * spec's additionalGids), -e entries append to env. The base document is
     * deep-copied via a JSON round-trip so the caller's Spec stays untouched.
     * Internal for unit tests.
     */
    @Suppress("LongParameterList")
    internal fun buildEffectiveProcess(
        base: Process?, user: String?, cwd: String?,
        envs: List<String>?, command: List<String>?,
        tty: Boolean, additionalGids: List<String>?, caps: List<String>?
    ): Process {
        if (base == null) {
            throw IllegalArgumentException("container config has no process section")
        }
        var p = base
        if (!command.isNullOrEmpty()) {
            p = p.copy(args = command)
        }
        if (p.args.isEmpty()) {
            throw IllegalArgumentException("no command specified")
        }
        p = p.copy(terminal = tty)
        if (user != null) {
            val uv = user.split(":")
            val uid = uv[0].toUInt()
            val gid = if (uv.size > 1) uv[1].toUInt() else p.user.gid
            p = p.copy(user = User(uid = uid, gid = gid, additionalGids = p.user.additionalGids))
        }
        if (!additionalGids.isNullOrEmpty()) {
            val existingGids = p.user.additionalGids ?: emptyList()
            p = p.copy(user = p.user.copy(additionalGids = existingGids + additionalGids.map { it.toUInt() }))
        }
        if (!caps.isNullOrEmpty()) {
            var capabilities = p.capabilities ?: LinuxCapabilities()
            for (cap in caps) {
                val c = if (cap.startsWith("CAP_")) cap else "CAP_$cap"
                capabilities = addCap(capabilities, c)
            }
            p = p.copy(capabilities = capabilities)
        }
        if (cwd != null) {
            p = p.copy(cwd = cwd)
        }
        if (!envs.isNullOrEmpty()) {
            p = p.copy(env = (p.env ?: emptyList()) + envs)
        }
        if (p.env == null) {
            p = p.copy(env = emptyList())
        }
        return p
    }

    private fun addCap(c: LinuxCapabilities, cap: String): LinuxCapabilities {
        val bounding = (c.bounding ?: emptyList()).let { if (cap in it) it else it + cap }
        val effective = (c.effective ?: emptyList()).let { if (cap in it) it else it + cap }
        val permitted = (c.permitted ?: emptyList()).let { if (cap in it) it else it + cap }
        val ambient = if (c.inheritable != null && cap in c.inheritable) {
            (c.ambient ?: emptyList()).let { if (cap in it) it else it + cap }
        } else c.ambient
        return c.copy(bounding = bounding, effective = effective, permitted = permitted, ambient = ambient)
    }

    /**
     * Fork and re-exec `/proc/self/exe __exec__` in the host namespaces,
     * then stream the payload to it. The child inherits the ns fds and the
     * payload socket because none of them carry CLOEXEC.
     */
    @Suppress("LongParameterList", "LongMethod")
    private fun spawn(
        arena: Arena, initPid: Int, payload: ExecPayload,
        cgroupPath: String?, detach: Boolean, pidFile: String?,
        affinity: ExecCPUAffinity?,
        cgroupExplicitRoot: Boolean, containerCgroupPath: String?,
        consoleSocket: String?, pidfdSocket: String?
    ): Int {
        val exePath = PosixIO.readlink(arena, "/proc/self/exe")
        if (exePath == null) {
            System.err.println("readlink /proc/self/exe failed")
            return EXIT_RUNTIME_ERROR
        }

        // Seccomp notify listener: the socket path only resolves on the host,
        // so connect here and let the fd travel to the restriction sequence.
        var seccompListenerFd = -1
        val seccomp = payload.seccomp
        if (seccomp != null) {
            val hasNotify = seccomp.hasNotifyAction()
            val listenerPath = seccomp.listenerPath
            if (hasNotify && listenerPath.isNullOrEmpty()) {
                System.err.println("seccomp listenerPath is not set")
                return EXIT_RUNTIME_ERROR
            }
            if (!listenerPath.isNullOrEmpty()) {
                seccompListenerFd = SeccompListener.connectHostSide(listenerPath)
                if (seccompListenerFd < 0) {
                    System.err.println(
                        "failed to connect with seccomp agent specified in the seccomp profile: " +
                            listenerPath
                    )
                    return EXIT_RUNTIME_ERROR
                }
            }
        }

        // Open the container's namespaces via the init pid. Absent files (e.g.
        // pre-timens kernel) are skipped, and so are namespaces the container
        // shares with us (same symlink target): joining them is a no-op at
        // best, and setns onto one's own user ns outright fails with EINVAL.
        // The fds are consumed by bootstrap.c's constructor in the __exec__
        // process (setns(mnt/user) must run before SubstrateVM spawns its
        // helper threads), in the order given here; any failure there is fatal.
        val nsFds = mutableListOf<Int>()
        val nsFdEntries = mutableListOf<String>()
        var cgroupNsFd = -1
        for (type in NS_ORDER) {
            val path = "/proc/$initPid/ns/$type"
            if (!Files.exists(Path.of(path))) continue
            val target = PosixIO.readlink(arena, path)
            val own = PosixIO.readlink(arena, "/proc/self/ns/$type")
            if (target != null && target == own) continue
            val fd = PosixIO.open(arena, path, Constants.O_RDONLY, 0)
            if (fd < 0) {
                Logger.warn("open $path failed: ${Libc.strerror(Libc.errno())}")
                continue
            }
            nsFds.add(fd)
            // Cgroup namespace must NOT be entered in bootstrap.c: the exec
            // process is moved to the container's cgroup by the CLI AFTER the
            // clone, so entering cgroupns before that makes /proc/self/cgroup
            // show a host-relative path instead of "0::/". We pass the fd
            // separately and do setns(cgroup) in ExecProcess after reading
            // the payload (which is the sync point for cgroup membership).
            if (type == "cgroup") {
                cgroupNsFd = fd
            } else {
                nsFdEntries.add("$type:$fd")
            }
        }

        val payloadFds = IntArray(2)
        if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, payloadFds) < 0) {
            System.err.println("socketpair failed: ${Libc.strerror(Libc.errno())}")
            return EXIT_RUNTIME_ERROR
        }
        val readFd = payloadFds[0]
        val writeFd = payloadFds[1]

        // "Exec ready" sync socketpair: ExecProcess writes a byte after all
        // process restrictions are applied; ExecCommand reads it before
        // writing the pid file. This ensures scheduler, capabilities, seccomp
        // etc. are in place by the time external observers inspect the pid.
        val execSyncFds = IntArray(2)
        var execSyncReadFd = -1  // ExecCommand reads from this
        var execSyncWriteFd = -1 // ExecProcess writes to this
        if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, execSyncFds) < 0) {
            Logger.warn("exec sync socketpair failed, pid file may race with restrictions")
        } else {
            execSyncReadFd = execSyncFds[0]
            execSyncWriteFd = execSyncFds[1]
        }

        // Console socketpair for exec -t: one end goes to ExecProcess so it
        // can send back the PTY master fd via SCM_RIGHTS after opening a pty
        // in the container's devpts.
        val wantTerminal = payload.process?.terminal == true
        var consoleReadFd = -1  // ExecCommand's end: receives master
        var consoleWriteFd = -1 // ExecProcess's end: sends master
        if (wantTerminal) {
            val consoleFds = IntArray(2)
            if (PosixIO.socketpair(
                    arena, Constants.AF_UNIX,
                    Constants.SOCK_STREAM, 0, consoleFds
                ) < 0
            ) {
                Logger.warn("console socketpair failed, PTY will be skipped")
            } else {
                consoleReadFd = consoleFds[0]
                consoleWriteFd = consoleFds[1]
            }
        }

        val envList = HostEnv.inherited()
        envList.add("_TAKOYAKI_EXEC_PAYLOAD_FD=$readFd")
        if (nsFdEntries.isNotEmpty()) {
            envList.add("_TAKOYAKI_EXEC_NS_FDS=${nsFdEntries.joinToString(",")}")
        }
        if (seccompListenerFd >= 0) {
            envList.add("_TAKOYAKI_SECCOMP_LISTENER_FD=$seccompListenerFd")
        }
        if (consoleWriteFd >= 0) {
            envList.add("_TAKOYAKI_EXEC_CONSOLE_FD=$consoleWriteFd")
        }
        if (cgroupNsFd >= 0) {
            envList.add("_TAKOYAKI_EXEC_CGROUPNS_FD=$cgroupNsFd")
        }
        if (execSyncWriteFd >= 0) {
            envList.add("_TAKOYAKI_EXEC_SYNC_FD=$execSyncWriteFd")
        }
        if (Logger.isDebugEnabled) {
            envList.add("_TAKOYAKI_EXEC_DEBUG=1")
        }
        // Propagate log file/format so bootstrap.c and ExecProcess can write
        // debug output to the same place the CLI's --log flag specified.
        val logFilePath = Logger.logFilePath
        if (logFilePath != null) {
            envList.add("_TAKOYAKI_LOG_FILE=$logFilePath")
        }
        val logFmt = Logger.formatName
        if (logFmt != null) {
            envList.add("_TAKOYAKI_LOG_FORMAT=$logFmt")
        }
        // Pass initial CPU affinity to bootstrap.c so it can set the affinity
        // on the parent thread before fork, letting the child inherit it.
        if (affinity != null && !affinity.initial.isNullOrEmpty()) {
            val mask = ExecCPUAffinity.parseCpuList(affinity.initial)
            envList.add("_TAKOYAKI_EXEC_CPU_INITIAL=0x${mask.toULong().toString(16)}")
        }

        val argv = arrayOf(exePath, "__exec__")
        // Shared arena, never closed: the forked child touches these segments
        // right up to execve (same pattern as CreateCommand).
        val execArena = Arena.ofShared()
        val execve = PosixIO.ExecvePayload.build(
            execArena, exePath, argv, envList.toTypedArray()
        )

        val payloadBytes = JsonCodec.encode(payload).toByteArray()

        val childPid = PosixIO.fork()
        if (childPid < 0) {
            System.err.println("fork failed: ${Libc.strerror(Libc.errno())}")
            return EXIT_RUNTIME_ERROR
        }
        if (childPid == 0) {
            // Close the write side so the payload read sees EOF once the
            // parent is done; everything else is meant to be inherited.
            PosixIO.close(writeFd)
            if (execSyncReadFd >= 0) PosixIO.close(execSyncReadFd)
            PosixIO.invokeExecve(execve)
            PosixIO._exit(1)
            return 1
        }

        PosixIO.close(readFd)
        if (execSyncWriteFd >= 0) PosixIO.close(execSyncWriteFd)
        for (fd in nsFds) PosixIO.close(fd)
        if (seccompListenerFd >= 0) PosixIO.close(seccompListenerFd)

        // bootstrap.c's exec_bootstrap reports the workload pid (in host pid
        // ns terms) as soon as it has setns'd and clone'd. EOF instead of a
        // pid means the bootstrap died before getting that far.
        val workloadPid: Int
        try {
            workloadPid = SyncChannel.readInt32(writeFd)
        } catch (e: RuntimeException) {
            System.err.println("no pid report from exec bootstrap: ${e.message}")
            PosixIO.close(writeFd)
            Wait.waitForChild(childPid)
            return EXIT_RUNTIME_ERROR
        }

        // Reap the intermediate, which exits right after the pid report. The
        // workload itself is also OUR child: exec_bootstrap clones it with
        // CLONE_PARENT, exactly like the create path's stage-2.
        Wait.waitForChild(childPid)

        if (pidfdSocket != null) {
            PidfdSocket.sendPidfd(pidfdSocket, workloadPid)
        }

        // Container cgroup membership BEFORE sending the payload: the workload
        // proceeds past its payload read only after we finish writing, so it
        // cannot reach user code outside the cgroup.
        // runc compat: when domain controllers are enabled and no explicit
        // --cgroup was given, joining the container root cgroup fails (EBUSY).
        // Fall back to the init process's current cgroup.
        val cgroupOk = Cgroup.addPid(cgroupPath, workloadPid.toLong())
        if (!cgroupOk && cgroupExplicitRoot) {
            // runc compat: --cgroup / explicitly requests the container root
            // cgroup. If the root cgroup has domain controllers enabled,
            // writing to cgroup.procs returns EBUSY. Report this as an error
            // rather than silently falling through.
            System.err.println(
                "error adding pid $workloadPid to cgroups: write ${Cgroup.dir(cgroupPath ?: "")}" +
                    "/cgroup.procs: device or resource busy"
            )
            // Kill the workload and return an error.
            Libc.kill(workloadPid, 9)
            Wait.waitForChild(workloadPid)
            PosixIO.close(writeFd)
            if (consoleWriteFd >= 0) PosixIO.close(consoleWriteFd)
            if (consoleReadFd >= 0) PosixIO.close(consoleReadFd)
            return EXIT_RUNTIME_ERROR
        }
        if (!cgroupOk && containerCgroupPath != null) {
            val initCgroup = Cgroup.readProcessCgroup(initPid)
            if (initCgroup != null) {
                // readProcessCgroup returns the absolute v2 path from the host
                // cgroup namespace (e.g. "/container-cg/foobar" or "/runc-tst-123").
                // Use it directly because init may have moved outside the
                // container's original cgroup entirely.
                Logger.debug("exec cgroup fallback to init's cgroup: $initCgroup")
                Cgroup.addPid(initCgroup, workloadPid.toLong())
            }
        }

        // runc compat: set final CPU affinity after cgroup assignment.
        // If affinity.final is set, apply that specific mask.
        // If no affinity is configured at all, reset to all CPUs (kernel
        // clamps to cpuset). If only initial was set, do nothing (initial
        // persists through the exec).
        val affinityFinal = affinity?.fin
        if (!affinityFinal.isNullOrEmpty()) {
            setCpuAffinity(workloadPid, affinityFinal)
        } else if (affinity == null || affinity.initial.isNullOrEmpty()) {
            resetCpuAffinity(workloadPid)
        }

        // Stream the payload; the workload drains concurrently, so there is no
        // socket-buffer deadlock however large the profile is. Closing our end
        // gives the workload's read its EOF.
        val written = PosixIO.writeAll(arena, writeFd, payloadBytes)
        if (!written) {
            System.err.println("payload write failed: ${Libc.strerror(Libc.errno())}")
            // Fall through: the workload sees a truncated payload, fails its
            // JSON parse and exits; reap it instead of leaving a zombie.
        }
        PosixIO.close(writeFd)
        if (consoleWriteFd >= 0) PosixIO.close(consoleWriteFd)

        // Receive the PTY master fd from ExecProcess. The workload opens a
        // pty in the container's devpts and sends the master back via
        // SCM_RIGHTS on the console socketpair.
        var masterFd = -1
        var ioThread: Thread? = null
        if (consoleReadFd >= 0) {
            masterFd = InternalConsole.receiveMasterFromSocket(consoleReadFd)
            PosixIO.close(consoleReadFd)
            if (masterFd >= 0 && consoleSocket != null) {
                // runc compat: forward the master fd to the external console
                // socket (e.g. recvtty) so the caller manages the PTY. This
                // is required for detached exec with --console-socket.
                ConsoleSocket.sendMasterTo(consoleSocket, masterFd)
            } else if (masterFd >= 0 && !detach) {
                ioThread = InternalConsole.startIOCopyForFd(masterFd)
            }
        }

        // Wait for the "exec ready" sync byte before writing the pid file.
        // ExecProcess sends this after applying all process restrictions
        // (scheduler, capabilities, seccomp) so the pid file only appears
        // once the workload is fully configured.
        if (execSyncReadFd >= 0 && written) {
            SyncChannel.readByte(execSyncReadFd)
            PosixIO.close(execSyncReadFd)
        }

        if (pidFile != null && written) {
            try {
                Files.writeString(Path.of(pidFile), workloadPid.toString())
            } catch (e: IOException) {
                System.err.println("write pid file failed: ${e.message}")
                return EXIT_RUNTIME_ERROR
            }
        }

        if (detach && written) {
            // Deliberately no wait: with no live ancestors the workload
            // reparents to the caller's subreaper -- containerd's shim relies
            // on that to reap a detached exec and observe its exit.
            if (masterFd >= 0) PosixIO.close(masterFd)
            return 0
        }
        val code = Wait.waitForChild(workloadPid)
        // Join the ioThread BEFORE closing masterFd so it can drain remaining
        // PTY output. Once the container exits the slave side closes, causing
        // read on the master to return EOF; closing the master prematurely
        // races with the reader and can lose the last chunk of output.
        if (ioThread != null) {
            try {
                ioThread.join(5_000)
            } catch (ignored: InterruptedException) {
            }
        }
        if (masterFd >= 0) PosixIO.close(masterFd)
        return if (written) code else EXIT_RUNTIME_ERROR
    }

    /** Set CPU affinity from a Linux CPU list string (e.g. "0-3,5"). */
    private fun setCpuAffinity(pid: Int, cpuList: String) {
        val mask = ExecCPUAffinity.parseCpuList(cpuList)
        Arena.ofConfined().use { arena ->
            val size = 128
            val seg = arena.allocate(size.toLong())
            seg.fill(0.toByte())
            // Write the mask in little-endian long order.
            seg.set(ValueLayout.JAVA_LONG_UNALIGNED, 0, mask)
            val rc = Libc.syscall(
                Constants.NR_sched_setaffinity,
                pid.toLong(), size.toLong(), seg.address(), 0L, 0L
            )
            if (rc != 0L) {
                Logger.debug("sched_setaffinity($pid, $cpuList): ${Libc.strerror(Libc.errno())}")
            }
        }
    }

    /** Reset CPU affinity of pid to all CPUs. See MainProcess.resetCpuAffinity. */
    private fun resetCpuAffinity(pid: Int) {
        Arena.ofConfined().use { arena ->
            val size = 128 // cpu_set_t: 1024 bits
            val mask = arena.allocate(size.toLong())
            mask.fill(0xFF.toByte())
            val rc = Libc.syscall(
                Constants.NR_sched_setaffinity,
                pid.toLong(), size.toLong(), mask.address(), 0L, 0L
            )
            if (rc != 0L) {
                Logger.debug("sched_setaffinity($pid): ${Libc.strerror(Libc.errno())}")
            }
        }
    }
}
