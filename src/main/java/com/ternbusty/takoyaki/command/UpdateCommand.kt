package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.cgroup.Cgroup
import com.ternbusty.takoyaki.config.KontainerConfig
import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.util.Json
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

        var r = Spec.LinuxResources()
        if (resourcesPath != null) {
            try {
                r = Json.readFile(Path.of(resourcesPath), Spec.LinuxResources::fromJson)!!
            } catch (e: Exception) {
                System.err.println("failed to read resources file: ${e.message}")
                return 1
            }
        }

        if (memory != null) {
            if (r.memory == null) r.memory = Spec.LinuxMemory()
            val mem = r.memory!!
            mem.limit = memory
            // runc compat: when memory limit is removed (-1), swap is also
            // removed unless an explicit --memory-swap value was given.
            if (memory == -1L && memorySwap == null && mem.swap == null) {
                mem.swap = -1L
            }
        }
        if (memoryReservation != null) {
            if (r.memory == null) r.memory = Spec.LinuxMemory()
            r.memory!!.reservation = memoryReservation
        }
        if (memorySwap != null) {
            if (r.memory == null) r.memory = Spec.LinuxMemory()
            val mem = r.memory!!
            mem.swap = memorySwap
            // For cgroup v2, swap is relative to memory. Need memory limit to
            // compute the delta. If memory was not given on this invocation,
            // read the current value from the cgroup.
            if (mem.limit == null) {
                try {
                    val cur = Files.readString(
                        Cgroup.dir(cgroupPath).resolve("memory.max")
                    ).trim()
                    if (cur != "max") {
                        mem.limit = cur.toLong()
                    }
                } catch (_: Exception) {
                }
            }
        }
        if (cpuQuota != null || cpuPeriod != null || cpuShares != null ||
            cpuBurst != null || cpuIdle != null
        ) {
            if (r.cpu == null) r.cpu = Spec.LinuxCpu()
            val cpu = r.cpu!!
            if (cpuQuota != null) cpu.quota = cpuQuota
            if (cpuPeriod != null) cpu.period = cpuPeriod
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
                            cpu.quota = if (parts[0] == "max") -1L else parts[0].toLong()
                        }
                        if (cpu.period == null) {
                            cpu.period = parts[1].toLong()
                        }
                    }
                } catch (_: Exception) {
                }
            }
            if (cpuShares != null) cpu.shares = cpuShares
            if (cpuBurst != null) cpu.burst = cpuBurst
            if (cpuIdle != null) {
                if (cpuIdle != 0L && cpuIdle != 1L) {
                    System.err.println("invalid value for cpu.idle: must be 0 or 1, got $cpuIdle")
                    return 1
                }
                cpu.idle = cpuIdle
            }
        }
        if (cpusetCpus != null) {
            if (r.cpu == null) r.cpu = Spec.LinuxCpu()
            r.cpu!!.cpus = cpusetCpus
        }
        if (pidsLimit != null) {
            if (r.pids == null) r.pids = Spec.LinuxPids()
            r.pids!!.limit = pidsLimit
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
