package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.spec.LinuxMemoryPolicy
import com.ternbusty.takoyaki.spec.LinuxSeccomp
import com.ternbusty.takoyaki.spec.Process
import kotlinx.serialization.Serializable

@Serializable
data class ExecPayload(
    val containerId: String? = null,
    val bundle: String? = null,
    val ociVersion: String? = null,
    val process: Process? = null,
    val seccomp: LinuxSeccomp? = null,
    val memoryPolicy: LinuxMemoryPolicy? = null,
    val preserveFds: Int = 0,
    val noNewKeyring: Boolean = false,
)
