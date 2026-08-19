package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.cgroup.Cgroup;
import com.ternbusty.takoyaki.config.KontainerConfig;
import com.ternbusty.takoyaki.ipc.SyncChannel;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.process.ExecPayload;
import com.ternbusty.takoyaki.seccomp.SeccompListener;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.util.Json;

import java.lang.foreign.Arena;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

/**
 * Run an additional command inside an existing container. Equivalent to
 * `runc exec`: the new process gets the container's namespaces AND the full
 * restriction set (cgroup membership, seccomp, capabilities, AppArmor/SELinux
 * label, no_new_privs, rlimits) re-applied, since none of those are inherited
 * through setns alone.
 *
 * Host-side half: resolves the effective process document and everything else
 * that needs host paths (config.json, cgroup path, seccomp listener socket,
 * /proc/&lt;init&gt;/ns fds), then forks and re-execs /proc/self/exe __exec__
 * while still in the host namespaces (see ExecProcess for why the re-exec
 * must precede setns). The payload travels over a socketpair.
 */
public final class ExecCommand {
    private ExecCommand() {}

    /** Namespaces to join, in application order (see ExecProcess). */
    private static final String[] NS_ORDER =
            {"user", "cgroup", "ipc", "uts", "net", "time", "pid", "mnt"};

    /** runc-compatible exit code for runtime-level exec errors. */
    private static final int EXIT_RUNTIME_ERROR = 255;

    public static int run(String rootPath, String containerId, String processJsonPath,
                          String user, String cwd, List<String> envs, List<String> command,
                          boolean detach, String pidFile, boolean tty, String consoleSocket,
                          List<String> additionalGids, List<String> caps, int preserveFds) {
        String exclusivity = exclusivityError(processJsonPath, user, cwd, envs, command);
        if (exclusivity != null) {
            System.err.println(exclusivity);
            return EXIT_RUNTIME_ERROR;
        }

        State state;
        try {
            state = State.load(rootPath, containerId).refreshStatus();
        } catch (Exception e) {
            System.err.println("container " + containerId + " does not exist");
            return EXIT_RUNTIME_ERROR;
        }
        if (state.statusEnum() == ContainerStatus.PAUSED) {
            System.err.println("cannot exec in a paused container");
            return EXIT_RUNTIME_ERROR;
        }
        if (state.statusEnum() != ContainerStatus.RUNNING || state.pid == null) {
            System.err.println("container " + containerId + " is not running");
            return EXIT_RUNTIME_ERROR;
        }

        Spec spec;
        try {
            spec = Json.readFile(Path.of(state.bundle, "config.json"), Spec::fromJson);
        } catch (Exception e) {
            System.err.println("failed to load config.json: " + e.getMessage());
            return EXIT_RUNTIME_ERROR;
        }

        // Effective process document: `-p FILE` verbatim (runc semantics), or
        // the container's own process section with CLI overrides applied.
        Spec.Process process;
        try {
            if (processJsonPath != null) {
                process = Json.readFile(Path.of(processJsonPath), Spec.Process::fromJson);
                if (process == null || process.args == null || process.args.isEmpty()) {
                    System.err.println("process.json has no args");
                    return EXIT_RUNTIME_ERROR;
                }
            } else {
                process = buildEffectiveProcess(spec.process, user, cwd, envs, command,
                        tty, additionalGids, caps);
            }
        } catch (Exception e) {
            System.err.println("failed to build process document: " + e.getMessage());
            return EXIT_RUNTIME_ERROR;
        }

        ExecPayload payload = new ExecPayload();
        payload.containerId = containerId;
        payload.bundle = state.bundle;
        payload.ociVersion = state.ociVersion;
        payload.process = process;
        payload.seccomp = spec.linux != null ? spec.linux.seccomp : null;
        // A missing runtime config just means a container created before cgroup
        // support (skip); any other load failure must NOT silently exec the
        // process outside the container's resource limits.
        String cgroupPath = null;
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath;
        } catch (java.nio.file.NoSuchFileException e) {
            Logger.debug("no cgroup config for " + containerId);
        } catch (Exception e) {
            System.err.println("failed to load cgroup config: " + e.getMessage());
            return EXIT_RUNTIME_ERROR;
        }

        try (Arena arena = Arena.ofConfined()) {
            return spawn(arena, state.pid, payload, cgroupPath, detach, pidFile);
        }
    }

    /**
     * `-p` hands over the whole process document, so combining it with the
     * flag-level overrides is ambiguous; runc resolves this by ignoring the
     * flags, we reject them outright. Returns an error message, or null when
     * the combination is fine. Package-visible for unit tests.
     */
    static String exclusivityError(String processJsonPath, String user, String cwd,
                                   List<String> envs, List<String> command) {
        if (processJsonPath == null) return null;
        if (user != null || cwd != null
                || (envs != null && !envs.isEmpty())
                || (command != null && !command.isEmpty())) {
            return "--process cannot be combined with -u/--cwd/-e or a command";
        }
        return null;
    }

    /**
     * The container's process section with exec CLI overrides applied on top:
     * positional command replaces args, -u replaces uid/gid (keeping the
     * spec's additionalGids), -e entries append to env. The base document is
     * deep-copied via a JSON round-trip so the caller's Spec stays untouched.
     * Package-visible for unit tests.
     */
    static Spec.Process buildEffectiveProcess(Spec.Process base, String user, String cwd,
                                              List<String> envs, List<String> command,
                                              boolean tty, List<String> additionalGids,
                                              List<String> caps) {
        if (base == null) {
            throw new IllegalArgumentException("container config has no process section");
        }
        Spec.Process p = Json.decode(Json.encode(base.toJson()), Spec.Process::fromJson);

        if (command != null && !command.isEmpty()) {
            p.args = new ArrayList<>(command);
        }
        if (p.args == null || p.args.isEmpty()) {
            throw new IllegalArgumentException("no command specified");
        }
        if (tty) {
            p.terminal = true;
        }
        if (user != null) {
            String[] uv = user.split(":");
            Spec.User u = new Spec.User();
            u.uid = Integer.parseInt(uv[0]);
            u.gid = uv.length > 1 ? Integer.parseInt(uv[1])
                    : (p.user != null ? p.user.gid : 0);
            u.additionalGids = p.user != null ? p.user.additionalGids : null;
            p.user = u;
        }
        if (additionalGids != null && !additionalGids.isEmpty()) {
            if (p.user == null) p.user = new Spec.User();
            List<Integer> gids = p.user.additionalGids != null
                    ? new ArrayList<>(p.user.additionalGids)
                    : new ArrayList<>();
            for (String g : additionalGids) {
                gids.add(Integer.parseInt(g));
            }
            p.user.additionalGids = gids;
        }
        if (caps != null && !caps.isEmpty()) {
            // --cap adds capabilities to all sets. Initialise from spec or empty.
            if (p.capabilities == null) p.capabilities = new Spec.LinuxCapabilities();
            for (String cap : caps) {
                String c = cap.startsWith("CAP_") ? cap : "CAP_" + cap;
                addCap(p.capabilities, c);
            }
        }
        if (cwd != null) {
            p.cwd = cwd;
        }
        if (envs != null && !envs.isEmpty()) {
            List<String> merged = p.env != null ? new ArrayList<>(p.env) : new ArrayList<>();
            merged.addAll(envs);
            p.env = merged;
        }
        if (p.env == null) {
            // No env anywhere in the spec. ExecProcess will add HOME from
            // /etc/passwd; no need to hardcode HOME here.
            p.env = List.of();
        }
        return p;
    }

    /**
     * runc's exec --cap adds the capability to bounding, effective, and
     * permitted. It does NOT add to inheritable. It adds to ambient only
     * if the capability is already present in inheritable (from the spec).
     */
    private static void addCap(Spec.LinuxCapabilities c, String cap) {
        if (c.bounding == null) c.bounding = new ArrayList<>();
        if (!c.bounding.contains(cap)) c.bounding.add(cap);
        if (c.effective == null) c.effective = new ArrayList<>();
        if (!c.effective.contains(cap)) c.effective.add(cap);
        if (c.permitted == null) c.permitted = new ArrayList<>();
        if (!c.permitted.contains(cap)) c.permitted.add(cap);
        // Ambient: only if already in inheritable.
        if (c.inheritable != null && c.inheritable.contains(cap)) {
            if (c.ambient == null) c.ambient = new ArrayList<>();
            if (!c.ambient.contains(cap)) c.ambient.add(cap);
        }
    }

    /**
     * Fork and re-exec {@code /proc/self/exe __exec__} in the host namespaces,
     * then stream the payload to it. The child inherits the ns fds and the
     * payload socket because none of them carry CLOEXEC.
     */
    private static int spawn(Arena arena, int initPid, ExecPayload payload,
                             String cgroupPath, boolean detach, String pidFile) {
        String exePath = PosixIO.readlink(arena, "/proc/self/exe");
        if (exePath == null) {
            System.err.println("readlink /proc/self/exe failed");
            return EXIT_RUNTIME_ERROR;
        }

        // Seccomp notify listener: the socket path only resolves on the host,
        // so connect here and let the fd travel to the restriction sequence.
        int seccompListenerFd = -1;
        if (payload.seccomp != null && payload.seccomp.listenerPath != null
                && !payload.seccomp.listenerPath.isEmpty()) {
            seccompListenerFd = SeccompListener.connectHostSide(payload.seccomp.listenerPath);
            if (seccompListenerFd < 0) {
                Logger.warn("could not connect to seccomp listener " + payload.seccomp.listenerPath
                        + "; SCMP_ACT_NOTIFY rules will block forever");
            }
        }

        // Open the container's namespaces via the init pid. Absent files (e.g.
        // pre-timens kernel) are skipped, and so are namespaces the container
        // shares with us (same symlink target): joining them is a no-op at
        // best, and setns onto one's own user ns outright fails with EINVAL.
        // The fds are consumed by bootstrap.c's constructor in the __exec__
        // process (setns(mnt/user) must run before SubstrateVM spawns its
        // helper threads), in the order given here; any failure there is fatal.
        List<Integer> nsFds = new ArrayList<>();
        StringJoiner nsFdList = new StringJoiner(",");
        for (String type : NS_ORDER) {
            String path = "/proc/" + initPid + "/ns/" + type;
            if (!java.nio.file.Files.exists(Path.of(path))) continue;
            String target = PosixIO.readlink(arena, path);
            String own = PosixIO.readlink(arena, "/proc/self/ns/" + type);
            if (target != null && target.equals(own)) continue;
            int fd = PosixIO.open(arena, path, Constants.O_RDONLY, 0);
            if (fd < 0) {
                Logger.warn("open " + path + " failed: " + Libc.strerror(Libc.errno()));
                continue;
            }
            nsFds.add(fd);
            nsFdList.add(type + ":" + fd);
        }

        int[] payloadFds = new int[2];
        if (PosixIO.socketpair(arena, Constants.AF_UNIX, Constants.SOCK_STREAM, 0, payloadFds) < 0) {
            System.err.println("socketpair failed: " + Libc.strerror(Libc.errno()));
            return EXIT_RUNTIME_ERROR;
        }
        int readFd = payloadFds[0];
        int writeFd = payloadFds[1];

        List<String> envList = HostEnv.inherited();
        envList.add("_TAKOYAKI_EXEC_PAYLOAD_FD=" + readFd);
        if (nsFdList.length() > 0) {
            envList.add("_TAKOYAKI_EXEC_NS_FDS=" + nsFdList);
        }
        if (seccompListenerFd >= 0) {
            envList.add("_TAKOYAKI_SECCOMP_LISTENER_FD=" + seccompListenerFd);
        }
        if (Logger.isDebugEnabled()) {
            envList.add("_TAKOYAKI_EXEC_DEBUG=1");
        }
        // Propagate log file/format so bootstrap.c and ExecProcess can write
        // debug output to the same place the CLI's --log flag specified.
        String logFilePath = Logger.getLogFilePath();
        if (logFilePath != null) {
            envList.add("_TAKOYAKI_LOG_FILE=" + logFilePath);
        }
        String logFmt = Logger.getFormatName();
        if (logFmt != null) {
            envList.add("_TAKOYAKI_LOG_FORMAT=" + logFmt);
        }

        String[] argv = {exePath, "__exec__"};
        // Shared arena, never closed: the forked child touches these segments
        // right up to execve (same pattern as CreateCommand).
        Arena execArena = Arena.ofShared();
        PosixIO.ExecvePayload execve = PosixIO.ExecvePayload.build(
                execArena, exePath, argv, envList.toArray(new String[0]));

        byte[] payloadBytes = Json.encode(payload.toJson()).getBytes();

        int childPid = PosixIO.fork();
        if (childPid < 0) {
            System.err.println("fork failed: " + Libc.strerror(Libc.errno()));
            return EXIT_RUNTIME_ERROR;
        }
        if (childPid == 0) {
            // Close the write side so the payload read sees EOF once the
            // parent is done; everything else is meant to be inherited.
            PosixIO.close(writeFd);
            PosixIO.invokeExecve(execve);
            PosixIO._exit(1);
            return 1;
        }

        PosixIO.close(readFd);
        for (int fd : nsFds) PosixIO.close(fd);
        if (seccompListenerFd >= 0) PosixIO.close(seccompListenerFd);

        // bootstrap.c's exec_bootstrap reports the workload pid (in host pid
        // ns terms) as soon as it has setns'd and clone'd. EOF instead of a
        // pid means the bootstrap died before getting that far.
        int workloadPid;
        try {
            workloadPid = SyncChannel.readInt32(writeFd);
        } catch (RuntimeException e) {
            System.err.println("no pid report from exec bootstrap: " + e.getMessage());
            PosixIO.close(writeFd);
            Wait.waitForChild(childPid);
            return EXIT_RUNTIME_ERROR;
        }

        // Reap the intermediate, which exits right after the pid report. The
        // workload itself is also OUR child: exec_bootstrap clones it with
        // CLONE_PARENT, exactly like the create path's stage-2.
        Wait.waitForChild(childPid);

        // Container cgroup membership BEFORE sending the payload: the workload
        // proceeds past its payload read only after we finish writing, so it
        // cannot reach user code outside the cgroup.
        Cgroup.addPid(cgroupPath, workloadPid);

        // Stream the payload; the workload drains concurrently, so there is no
        // socket-buffer deadlock however large the profile is. Closing our end
        // gives the workload's read its EOF.
        boolean written = PosixIO.writeAll(arena, writeFd, payloadBytes);
        if (!written) {
            System.err.println("payload write failed: " + Libc.strerror(Libc.errno()));
            // Fall through: the workload sees a truncated payload, fails its
            // JSON parse and exits; reap it instead of leaving a zombie.
        }
        PosixIO.close(writeFd);

        if (pidFile != null && written) {
            try {
                java.nio.file.Files.writeString(Path.of(pidFile), Integer.toString(workloadPid));
            } catch (java.io.IOException e) {
                System.err.println("write pid file failed: " + e.getMessage());
                return EXIT_RUNTIME_ERROR;
            }
        }

        if (detach && written) {
            // Deliberately no wait: with no live ancestors the workload
            // reparents to the caller's subreaper — containerd's shim relies
            // on that to reap a detached exec and observe its exit.
            return 0;
        }
        int code = Wait.waitForChild(workloadPid);
        return written ? code : EXIT_RUNTIME_ERROR;
    }
}
