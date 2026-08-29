package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.util.Json
import java.io.IOException
import java.nio.file.Files

object PsCommand {

    fun run(
        rootPath: String,
        containerId: String,
        format: String?,
        psArgs: List<String>?,
    ): Int {
        val state: State
        try {
            state = State.load(rootPath, containerId).refreshStatus()
        } catch (e: Exception) {
            Logger.error("failed to load state: ${e.message}")
            return 1
        }

        var cgroupPath: String? = null
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath
        } catch (_: IOException) {
        }

        val pids = mutableListOf<Int>()
        if (cgroupPath != null) {
            val procs = Cgroup.dir(cgroupPath).resolve("cgroup.procs")
            try {
                for (line in Files.readAllLines(procs)) {
                    val t = line.trim()
                    if (t.isNotEmpty()) pids.add(t.toInt())
                }
            } catch (e: IOException) {
                Logger.debug("read $procs failed: ${e.message}")
            }
        }
        val statePid = state.pid
        if (pids.isEmpty() && statePid != null) pids.add(statePid)

        if (format == "json") {
            println(Json.encode(pids))
            return 0
        }
        // Run the host "ps" command and filter to only container pids.
        // runc default is "ps -ef" when no extra args are given.
        return runHostPs(pids, psArgs)
    }

    /** Execute host ps and filter output to only show container PIDs. */
    private fun runHostPs(pids: List<Int>, psArgs: List<String>?): Int {
        val pidSet = pids.toHashSet()
        val cmd = mutableListOf("ps")
        if (psArgs.isNullOrEmpty()) {
            cmd.add("-ef")
        } else {
            cmd.addAll(psArgs)
        }
        try {
            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(true)
            val p = pb.start()
            val output = String(p.inputStream.readAllBytes())
            val rc = p.waitFor()
            if (rc != 0) {
                System.err.print(output)
                return rc
            }
            val lines = output.split("\n")
            if (lines.isNotEmpty()) {
                // Print header
                println(lines[0])
            }
            for (i in 1 until lines.size) {
                // Extract PID from the line. For "ps -ef" format, PID is the
                // second whitespace-delimited field. For "ps -e -x" format,
                // PID is the first field (possibly with leading spaces).
                val line = lines[i]
                val pidFromLine = extractPid(line)
                if (pidFromLine >= 0 && pidFromLine in pidSet) {
                    println(line)
                }
            }
            return 0
        } catch (e: Exception) {
            System.err.println("failed to run ps: ${e.message}")
            return 1
        }
    }

    /** Extract PID from a ps output line. Tries multiple common formats. */
    private fun extractPid(line: String): Int {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 2) return -1
        // Try first field (BSD-style: PID TTY STAT ...)
        parts[0].toIntOrNull()?.let { return it }
        // Try second field (SysV-style: UID PID PPID ...)
        parts[1].toIntOrNull()?.let { return it }
        return -1
    }
}
