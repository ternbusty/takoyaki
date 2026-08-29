package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.state.ContainerStatus
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.SyscallHost
import java.nio.file.Files

object KillCommand {

    fun run(rootPath: String, containerId: String, signal: String, all: Boolean): Int {
        val sig: Int
        try {
            sig = parseSignal(signal)
        } catch (e: IllegalArgumentException) {
            System.err.println("invalid signal: $signal")
            return 1
        }
        val state: State
        try {
            state = State.load(rootPath, containerId).refreshStatus()
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            return 1
        }
        if (!state.statusEnum().canKill()) {
            // runc compat: when the container uses the host PID namespace, the
            // init process may die while worker processes remain alive in the
            // cgroup. Allow kill if the cgroup still has processes.
            var cgroupAlive = false
            if (state.statusEnum() == ContainerStatus.STOPPED) {
                try {
                    val kc = KontainerConfig.load(rootPath, containerId)
                    val cgPath = kc.cgroupPath
                    if (cgPath != null) {
                        val procsFile = Cgroup.dir(cgPath).resolve("cgroup.procs")
                        if (Files.exists(procsFile)) {
                            val content = Files.readString(procsFile).trim()
                            cgroupAlive = content.isNotEmpty()
                        }
                    }
                } catch (_: Exception) {
                }
            }
            if (!cgroupAlive) {
                if (all) return 0 // -a suppresses error for stopped containers
                System.err.println("container not running")
                return 1
            }
        }

        // Try cgroup-based kill first (covers host pidns and multi-process
        // containers). Fall back to direct pid kill.
        var killed = false
        try {
            val kc = KontainerConfig.load(rootPath, containerId)
            val cgPath2 = kc.cgroupPath
            if (cgPath2 != null) {
                killed = killViaCgroup(cgPath2, sig)
            }
        } catch (e: Exception) {
            Logger.debug("no cgroup config for kill: ${e.message}")
        }

        val statePid = state.pid
        if (!killed && statePid != null) {
            val sc = SyscallHost.current()
            val rc = sc.kill(statePid, sig)
            if (rc != 0 && sc.errno() != Constants.ESRCH) {
                System.err.println("kill failed: ${sc.strerror(sc.errno())}")
                return 1
            }
            killed = true
        }
        if (!killed && state.pid == null) {
            System.err.println("container $containerId has no process to kill")
            return 1
        }
        Logger.info("sent signal $signal to container $containerId")
        return 0
    }

    /**
     * Kill all processes in the container's cgroup. Returns true if at
     * least one process was signalled.
     */
    private fun killViaCgroup(cgroupPath: String, sig: Int): Boolean {
        val procsFile = Cgroup.dir(cgroupPath).resolve("cgroup.procs")
        if (!Files.exists(procsFile)) return false
        var any = false
        val sc = SyscallHost.current()
        try {
            // Kill in a loop until cgroup.procs is empty (new forks can appear)
            for (attempts in 0 until 10) {
                val content = Files.readString(procsFile).trim()
                if (content.isEmpty()) break
                for (line in content.split("\n")) {
                    try {
                        val pid = line.trim().toInt()
                        sc.kill(pid, sig)
                        any = true
                    } catch (_: NumberFormatException) {
                    }
                }
                Thread.sleep(10)
            }
        } catch (e: Exception) {
            Logger.debug("cgroup kill failed: ${e.message}")
        }
        return any
    }

    fun parseSignal(s: String): Int {
        s.toIntOrNull()?.let { return it }
        // Normalize case BEFORE checking the SIG prefix; otherwise "sigterm"
        // gets prefixed again to "SIGsigterm" and falls through to default.
        val upper = s.uppercase()
        val n = if (upper.startsWith("SIG")) upper else "SIG$upper"
        return when (n) {
            "SIGHUP" -> Constants.SIGHUP
            "SIGINT" -> Constants.SIGINT
            "SIGQUIT" -> Constants.SIGQUIT
            "SIGILL" -> Constants.SIGILL
            "SIGABRT" -> Constants.SIGABRT
            "SIGFPE" -> Constants.SIGFPE
            "SIGKILL" -> Constants.SIGKILL
            "SIGSEGV" -> Constants.SIGSEGV
            "SIGPIPE" -> Constants.SIGPIPE
            "SIGALRM" -> Constants.SIGALRM
            "SIGTERM" -> Constants.SIGTERM
            "SIGUSR1" -> Constants.SIGUSR1
            "SIGUSR2" -> Constants.SIGUSR2
            "SIGCHLD" -> Constants.SIGCHLD
            "SIGCONT" -> Constants.SIGCONT
            "SIGSTOP" -> Constants.SIGSTOP
            "SIGTSTP" -> Constants.SIGTSTP
            "SIGTTIN" -> Constants.SIGTTIN
            "SIGTTOU" -> Constants.SIGTTOU
            else -> throw IllegalArgumentException("unknown signal: $s")
        }
    }
}
