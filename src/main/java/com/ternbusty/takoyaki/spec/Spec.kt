package com.ternbusty.takoyaki.spec

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Spec(
    val ociVersion: String = "1.0.0",
    val root: Root? = null,
    val process: Process? = null,
    val hostname: String? = null,
    val domainname: String? = null,
    val mounts: List<Mount>? = null,
    val annotations: Map<String, String>? = null,
    val hooks: Hooks? = null,
    val linux: Linux? = null,
) {
    fun hasNamespace(type: String): Boolean =
        linux?.namespaces?.any { it.type == type } ?: false

    fun createsNamespace(type: String): Boolean =
        linux?.namespaces?.any { it.type == type && it.path.isNullOrEmpty() } ?: false
}

@Serializable
data class Root(
    val path: String? = null,
    val readonly: Boolean = false,
)

@Serializable
data class Process(
    val args: List<String> = emptyList(),
    val env: List<String>? = null,
    val cwd: String = "/",
    val noNewPrivileges: Boolean? = null,
    val user: User = User(),
    val capabilities: LinuxCapabilities? = null,
    val rlimits: List<POSIXRlimit>? = null,
    val umask: Long? = null,
    val oomScoreAdj: Int? = null,
    val apparmorProfile: String? = null,
    val selinuxLabel: String? = null,
    val terminal: Boolean = false,
    val consoleSize: ConsoleSize? = null,
    val ioPriority: LinuxIOPriority? = null,
    val scheduler: LinuxScheduler? = null,
    val execCPUAffinity: ExecCPUAffinity? = null,
)

@Serializable
data class ConsoleSize(
    val height: Int = 0,
    val width: Int = 0,
)

@Serializable
data class User(
    val uid: Int = 0,
    val gid: Int = 0,
    val umask: Long? = null,
    val additionalGids: List<Int>? = null,
)

@Serializable
data class POSIXRlimit(
    val type: String? = null,
    val hard: Long = 0,
    val soft: Long = 0,
)

@Serializable
data class LinuxCapabilities(
    val bounding: List<String>? = null,
    val effective: List<String>? = null,
    val inheritable: List<String>? = null,
    val permitted: List<String>? = null,
    val ambient: List<String>? = null,
)

@Serializable
data class Hook(
    val path: String? = null,
    val args: List<String>? = null,
    val env: List<String>? = null,
    val timeout: Long? = null,
)

@Serializable
data class Hooks(
    val prestart: List<Hook>? = null,
    val createRuntime: List<Hook>? = null,
    val createContainer: List<Hook>? = null,
    val startContainer: List<Hook>? = null,
    val poststart: List<Hook>? = null,
    val poststop: List<Hook>? = null,
)

@Serializable
data class Mount(
    val destination: String? = null,
    val source: String? = null,
    val type: String? = null,
    val options: List<String>? = null,
    val uidMappings: List<LinuxIdMapping>? = null,
    val gidMappings: List<LinuxIdMapping>? = null,
)

@Serializable
data class Namespace(
    val type: String? = null,
    val path: String? = null,
)

@Serializable
data class LinuxIdMapping(
    val containerID: Long = 0,
    val hostID: Long = 0,
    val size: Long = 0,
)

@Serializable
data class LinuxMemory(
    val limit: Long? = null,
    val reservation: Long? = null,
    val swap: Long? = null,
    val checkBeforeUpdate: Boolean? = null,
)

@Serializable
data class LinuxCpu(
    val shares: Long? = null,
    val quota: Long? = null,
    val period: Long? = null,
    val cpus: String? = null,
    val mems: String? = null,
    val realtimePeriod: Long? = null,
    val realtimeRuntime: Long? = null,
    val burst: Long? = null,
    val idle: Long? = null,
)

@Serializable
data class LinuxPids(
    val limit: Long = 0,
)

@Serializable
data class LinuxHugepageLimit(
    val pageSize: String? = null,
    val limit: Long? = null,
)

@Serializable
data class LinuxDeviceCgroup(
    val allow: Boolean = false,
    val type: String? = null,
    val major: Long? = null,
    val minor: Long? = null,
    val access: String? = null,
)

@Serializable
data class LinuxThrottleDevice(
    val major: Long? = null,
    val minor: Long? = null,
    val rate: Long? = null,
)

@Serializable
data class LinuxBlockIO(
    val weight: Long? = null,
    val leafWeight: Long? = null,
    val throttleReadBpsDevice: List<LinuxThrottleDevice>? = null,
    val throttleWriteBpsDevice: List<LinuxThrottleDevice>? = null,
    val throttleReadIOPSDevice: List<LinuxThrottleDevice>? = null,
    val throttleWriteIOPSDevice: List<LinuxThrottleDevice>? = null,
)

@Serializable
data class LinuxResources(
    val devices: List<LinuxDeviceCgroup>? = null,
    val pids: LinuxPids? = null,
    val hugepageLimits: List<LinuxHugepageLimit>? = null,
    val memory: LinuxMemory? = null,
    val cpu: LinuxCpu? = null,
    val unified: Map<String, String>? = null,
    val blockIO: LinuxBlockIO? = null,
)

@Serializable
data class SeccompArg(
    val index: Int = 0,
    val value: Long = 0,
    val valueTwo: Long? = null,
    val op: String? = null,
)

@Serializable
data class LinuxSyscall(
    val names: List<String>? = null,
    val action: String? = null,
    val errnoRet: Long? = null,
    val args: List<SeccompArg>? = null,
)

@Serializable
data class LinuxSeccomp(
    val defaultAction: String? = null,
    val defaultErrnoRet: Long? = null,
    val architectures: List<String>? = null,
    val syscalls: List<LinuxSyscall>? = null,
    val flags: List<String>? = null,
    val listenerPath: String? = null,
    val listenerMetadata: String? = null,
) {
    fun hasNotifyAction(): Boolean =
        syscalls?.any { it.action == "SCMP_ACT_NOTIFY" } ?: false
}

@Serializable
data class LinuxDevice(
    val path: String? = null,
    val type: String? = null,
    val major: Long? = null,
    val minor: Long? = null,
    val fileMode: Long? = null,
    val uid: Long? = null,
    val gid: Long? = null,
)

@Serializable
data class LinuxIOPriority(
    @SerialName("class") val clazz: String? = null,
    val priority: Int = 0,
) {
    fun classValue(): Int = when (clazz) {
        "IOPRIO_CLASS_RT" -> 1
        "IOPRIO_CLASS_BE" -> 2
        "IOPRIO_CLASS_IDLE" -> 3
        else -> 2
    }
}

@Serializable
data class LinuxScheduler(
    val policy: String? = null,
    val nice: Int? = null,
    val priority: Int? = null,
    val flags: List<String>? = null,
    val runtime: Long? = null,
    val deadline: Long? = null,
    val period: Long? = null,
) {
    fun policyValue(): Int = when (policy) {
        "SCHED_OTHER" -> 0
        "SCHED_FIFO" -> 1
        "SCHED_RR" -> 2
        "SCHED_BATCH" -> 3
        "SCHED_ISO" -> 4
        "SCHED_IDLE" -> 5
        "SCHED_DEADLINE" -> 6
        else -> 0
    }

    fun flagBits(): Long {
        if (flags.isNullOrEmpty()) return 0
        var bits = 0L
        for (f in flags) {
            bits = bits or when (f) {
                "SCHED_FLAG_RESET_ON_FORK" -> 0x01L
                "SCHED_FLAG_RECLAIM" -> 0x02L
                "SCHED_FLAG_DL_OVERRUN" -> 0x04L
                "SCHED_FLAG_KEEP_POLICY" -> 0x08L
                "SCHED_FLAG_KEEP_PARAMS" -> 0x10L
                "SCHED_FLAG_UTIL_CLAMP_MIN" -> 0x20L
                "SCHED_FLAG_UTIL_CLAMP_MAX" -> 0x40L
                else -> 0L
            }
        }
        return bits
    }
}

@Serializable
data class ExecCPUAffinity(
    val initial: String? = null,
    @SerialName("final") val fin: String? = null,
) {
    companion object {
        fun parseCpuList(list: String?): Long {
            if (list.isNullOrEmpty()) return 0
            var mask = 0L
            for (part in list.split(",")) {
                val trimmed = part.trim()
                val dash = trimmed.indexOf('-')
                if (dash >= 0) {
                    val lo = trimmed.substring(0, dash).trim().toInt()
                    val hi = trimmed.substring(dash + 1).trim().toInt()
                    for (i in lo..hi) {
                        if (i >= 64) break
                        mask = mask or (1L shl i)
                    }
                } else {
                    val cpu = trimmed.toInt()
                    if (cpu < 64) mask = mask or (1L shl cpu)
                }
            }
            return mask
        }
    }
}

@Serializable
data class LinuxTimeOffset(
    val secs: Long = 0,
    val nanosecs: Long = 0,
)

@Serializable
data class Linux(
    val namespaces: List<Namespace>? = null,
    val uidMappings: List<LinuxIdMapping>? = null,
    val gidMappings: List<LinuxIdMapping>? = null,
    val resources: LinuxResources? = null,
    val cgroupsPath: String? = null,
    val seccomp: LinuxSeccomp? = null,
    val devices: List<LinuxDevice>? = null,
    val maskedPaths: List<String>? = null,
    val readonlyPaths: List<String>? = null,
    val rootfsPropagation: String? = null,
    val sysctl: Map<String, String>? = null,
    val timeOffsets: Map<String, LinuxTimeOffset>? = null,
    val memoryPolicy: LinuxMemoryPolicy? = null,
    val netDevices: Map<String, LinuxNetDevice>? = null,
)

@Serializable
data class LinuxMemoryPolicy(
    val mode: String? = null,
    val nodes: String? = null,
    val flags: List<String>? = null,
)

@Serializable
data class LinuxNetDevice(
    val name: String? = null,
)
