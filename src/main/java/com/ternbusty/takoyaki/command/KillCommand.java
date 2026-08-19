package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.SyscallHost;
import com.ternbusty.takoyaki.syscall.Syscalls;

public final class KillCommand {
    private KillCommand() {}

    public static int run(String rootPath, String containerId, String signal, boolean all) {
        int sig;
        try { sig = parseSignal(signal); }
        catch (IllegalArgumentException e) {
            System.err.println("invalid signal: " + signal);
            return 1;
        }
        State state;
        try {
            state = State.load(rootPath, containerId).refreshStatus();
        } catch (Exception e) {
            System.err.println("container " + containerId + " does not exist");
            return 1;
        }
        if (!state.statusEnum().canKill()) {
            // runc compat: when the container uses the host PID namespace, the
            // init process may die while worker processes remain alive in the
            // cgroup. Allow kill if the cgroup still has processes.
            boolean cgroupAlive = false;
            if (state.statusEnum() == com.ternbusty.takoyaki.state.ContainerStatus.STOPPED) {
                try {
                    var kc = com.ternbusty.takoyaki.config.KontainerConfig.load(rootPath, containerId);
                    if (kc.cgroupPath != null) {
                        java.nio.file.Path procsFile = com.ternbusty.takoyaki.cgroup.Cgroup.dir(kc.cgroupPath)
                                .resolve("cgroup.procs");
                        if (java.nio.file.Files.exists(procsFile)) {
                            String content = java.nio.file.Files.readString(procsFile).trim();
                            cgroupAlive = !content.isEmpty();
                        }
                    }
                } catch (Exception ignored) {}
            }
            if (!cgroupAlive) {
                if (all) return 0; // -a suppresses error for stopped containers
                System.err.println("container not running");
                return 1;
            }
        }

        // Try cgroup-based kill first (covers host pidns and multi-process
        // containers). Fall back to direct pid kill.
        boolean killed = false;
        try {
            var kc = com.ternbusty.takoyaki.config.KontainerConfig.load(rootPath, containerId);
            if (kc.cgroupPath != null) {
                killed = killViaCgroup(kc.cgroupPath, sig);
            }
        } catch (Exception e) {
            Logger.debug("no cgroup config for kill: " + e.getMessage());
        }

        if (!killed && state.pid != null) {
            Syscalls sc = SyscallHost.current();
            int rc = sc.kill(state.pid, sig);
            if (rc != 0 && sc.errno() != Constants.ESRCH) {
                System.err.println("kill failed: " + sc.strerror(sc.errno()));
                return 1;
            }
        }
        Logger.info("sent signal " + signal + " to container " + containerId);
        return 0;
    }

    /** Kill all processes in the container's cgroup. Returns true if at
     *  least one process was signalled. */
    private static boolean killViaCgroup(String cgroupPath, int sig) {
        java.nio.file.Path procsFile = com.ternbusty.takoyaki.cgroup.Cgroup.dir(cgroupPath)
                .resolve("cgroup.procs");
        if (!java.nio.file.Files.exists(procsFile)) return false;
        boolean any = false;
        Syscalls sc = SyscallHost.current();
        try {
            // Kill in a loop until cgroup.procs is empty (new forks can appear)
            for (int attempts = 0; attempts < 10; attempts++) {
                String content = java.nio.file.Files.readString(procsFile).trim();
                if (content.isEmpty()) break;
                for (String line : content.split("\n")) {
                    try {
                        int pid = Integer.parseInt(line.trim());
                        sc.kill(pid, sig);
                        any = true;
                    } catch (NumberFormatException ignored) {}
                }
                Thread.sleep(10);
            }
        } catch (Exception e) {
            Logger.debug("cgroup kill failed: " + e.getMessage());
        }
        return any;
    }

    public static int parseSignal(String s) {
        try { return Integer.parseInt(s); } catch (NumberFormatException ignored) {}
        // Normalize case BEFORE checking the SIG prefix; otherwise "sigterm"
        // gets prefixed again to "SIGsigterm" and falls through to default.
        String upper = s.toUpperCase();
        String n = upper.startsWith("SIG") ? upper : "SIG" + upper;
        return switch (n) {
            case "SIGHUP" -> Constants.SIGHUP;
            case "SIGINT" -> Constants.SIGINT;
            case "SIGQUIT" -> Constants.SIGQUIT;
            case "SIGILL" -> Constants.SIGILL;
            case "SIGABRT" -> Constants.SIGABRT;
            case "SIGFPE" -> Constants.SIGFPE;
            case "SIGKILL" -> Constants.SIGKILL;
            case "SIGSEGV" -> Constants.SIGSEGV;
            case "SIGPIPE" -> Constants.SIGPIPE;
            case "SIGALRM" -> Constants.SIGALRM;
            case "SIGTERM" -> Constants.SIGTERM;
            case "SIGUSR1" -> Constants.SIGUSR1;
            case "SIGUSR2" -> Constants.SIGUSR2;
            case "SIGCHLD" -> Constants.SIGCHLD;
            case "SIGCONT" -> Constants.SIGCONT;
            case "SIGSTOP" -> Constants.SIGSTOP;
            case "SIGTSTP" -> Constants.SIGTSTP;
            case "SIGTTIN" -> Constants.SIGTTIN;
            case "SIGTTOU" -> Constants.SIGTTOU;
            default -> throw new IllegalArgumentException("unknown signal: " + s);
        };
    }
}
