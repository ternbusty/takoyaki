package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import java.io.IOException
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.util.JsonCodec
import java.nio.file.Files
import java.nio.file.Path

object UpdateCommand {

    fun run(
        rootPath: String,
        containerId: String,
        resourcesPath: String?,
        memory: Long?,
        memoryReservation: Long?,
        memorySwap: Long?,
        cpuQuota: Long?,
        cpuPeriod: Long?,
        cpuShares: Long?,
        pidsLimit: Long?,
        cpusetCpus: String?,
        cpuBurst: Long?,
        cpuIdle: Long?,
    ): Int {
        val cgroupPath: String
        try {
            cgroupPath = KontainerConfig.load(rootPath, containerId).cgroupPath
                ?: run {
                    System.err.println("container has no cgroupsPath")
                    return 1
                }
        } catch (e: Exception) {
            System.err.println("container $containerId does not exist")
            return 1
        }

        var r = LinuxResources()
        if (resourcesPath != null) {
            try {
                r = JsonCodec.loadFromFile<LinuxResources>(Path.of(resourcesPath))
                    ?: throw IOException("failed to parse resources file")
            } catch (e: Exception) {
                System.err.println("failed to read resources file: ${e.message}")
                return 1
            }
        }

        if (memory != null) {
            var mem = (r.memory ?: LinuxMemory()).copy(limit = memory)
            // runc compat: when memory limit is removed (-1), swap is also
            // removed unless an explicit --memory-swap value was given.
            if (memory == -1L && memorySwap == null && mem.swap == null) {
                mem = mem.copy(swap = -1L)
            }
            r = r.copy(memory = mem)
        }
        if (memoryReservation != null) {
            r = r.copy(memory = (r.memory ?: LinuxMemory()).copy(reservation = memoryReservation))
        }
        if (memorySwap != null) {
            var mem = (r.memory ?: LinuxMemory()).copy(swap = memorySwap)
            // For cgroup v2, swap is relative to memory. Need memory limit to
            // compute the delta. If memory was not given on this invocation,
            // read the current value from the cgroup.
            if (mem.limit == null) {
                try {
                    val cur = Files.readString(
                        Cgroup.dir(cgroupPath).resolve("memory.max")
                    ).trim()
                    if (cur != "max") {
                        mem = mem.copy(limit = cur.toLong())
                    }
                } catch (_: Exception) {
                }
            }
            r = r.copy(memory = mem)
        }
        if (cpuQuota != null || cpuPeriod != null || cpuShares != null ||
            cpuBurst != null || cpuIdle != null
        ) {
            var cpu = r.cpu ?: LinuxCpu()
            if (cpuQuota != null) cpu = cpu.copy(quota = cpuQuota)
            if (cpuPeriod != null) cpu = cpu.copy(period = cpuPeriod)
            // runc compat: when only period or only quota is given via CLI,
            // read the current cpu.max and preserve the other component.
            // Without this, the missing component defaults to "max"/100000
            // and the update clobbers the previous value.
            if ((cpuQuota != null || cpuPeriod != null) &&
                (cpu.quota == null || cpu.period == null)
            ) {
                try {
                    val cpuMax = Files.readString(
                        Cgroup.dir(cgroupPath).resolve("cpu.max")
                    ).trim()
                    val parts = cpuMax.split("\\s+".toRegex())
                    if (parts.size == 2) {
                        if (cpu.quota == null) {
                            cpu = cpu.copy(quota = if (parts[0] == "max") -1L else parts[0].toLong())
                        }
                        if (cpu.period == null) {
                            cpu = cpu.copy(period = parts[1].toLong())
                        }
                    }
                } catch (_: Exception) {
                }
            }
            if (cpuShares != null) cpu = cpu.copy(shares = cpuShares)
            if (cpuBurst != null) cpu = cpu.copy(burst = cpuBurst)
            if (cpuIdle != null) {
                if (cpuIdle != 0L && cpuIdle != 1L) {
                    System.err.println("invalid value for cpu.idle: must be 0 or 1, got $cpuIdle")
                    return 1
                }
                cpu = cpu.copy(idle = cpuIdle)
            }
            r = r.copy(cpu = cpu)
        }
        if (cpusetCpus != null) {
            r = r.copy(cpu = (r.cpu ?: LinuxCpu()).copy(cpus = cpusetCpus))
        }
        if (pidsLimit != null) {
            r = r.copy(pids = (r.pids ?: LinuxPids()).copy(limit = pidsLimit))
        }

        // Validate cpu.idle regardless of source (CLI or JSON).
        val validCpu = r.cpu
        val validIdle = validCpu?.idle
        if (validCpu != null && validIdle != null && validIdle != 0L && validIdle != 1L) {
            System.err.println("invalid value for cpu.idle: must be 0 or 1, got $validIdle")
            return 1
        }

        // runc compat: checkBeforeUpdate prevents setting memory limits
        // below current usage, avoiding instant OOM kills.
        // Check swap first: when both memory and swap are below usage, runc
        // reports "rejecting memory+swap limit" (the more specific error).
        val checkMem = r.memory
        if (checkMem != null && checkMem.checkBeforeUpdate == true) {
            val cgDir = Cgroup.dir(cgroupPath)
            val memSwap = checkMem.swap
            val memLimit = checkMem.limit
            if (memSwap != null && memSwap > 0 && memLimit != null) {
                val memUsage = readCgroupLong(cgDir.resolve("memory.current"))
                val swapUsage = readCgroupLong(cgDir.resolve("memory.swap.current"))
                val totalUsage = memUsage + swapUsage
                if (totalUsage > 0 && memSwap < totalUsage) {
                    System.err.println(
                        "rejecting memory+swap limit $memSwap" +
                            " (current usage is $totalUsage)"
                    )
                    return 1
                }
            }
            if (memLimit != null && memLimit > 0) {
                val usage = readCgroupLong(cgDir.resolve("memory.current"))
                if (usage > 0 && memLimit < usage) {
                    System.err.println(
                        "rejecting memory limit $memLimit" +
                            " (current usage is $usage)"
                    )
                    return 1
                }
            }
        }

        Cgroup.applyLimitsOnly(cgroupPath, r)
        return 0
    }

    private fun readCgroupLong(p: Path): Long =
        try {
            val v = Files.readString(p).trim()
            if (v == "max") Long.MAX_VALUE else v.toLong()
        } catch (_: Exception) {
            -1
        }
}
