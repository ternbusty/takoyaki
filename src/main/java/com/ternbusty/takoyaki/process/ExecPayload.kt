package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.spec.Spec
import com.ternbusty.takoyaki.util.json.JsonMap

/**
 * Everything the `__exec__` process needs, serialized by ExecCommand
 * into the payload socket. The exec side cannot re-read config.json itself:
 * after setns(mnt) the bundle path no longer resolves, so the host side
 * snapshots the effective process document (and the container's seccomp
 * profile) before the namespace transition.
 */
class ExecPayload {
    var containerId: String? = null
    var bundle: String? = null
    var ociVersion: String? = null
    var process: Spec.Process? = null
    var seccomp: Spec.LinuxSeccomp? = null
    var memoryPolicy: Spec.MemoryPolicy? = null
    var preserveFds: Int = 0
    var noNewKeyring: Boolean = false

    fun toJson(): Any {
        val o = JsonMap.obj()
        JsonMap.put(o, "containerId", containerId)
        JsonMap.put(o, "bundle", bundle)
        JsonMap.put(o, "ociVersion", ociVersion)
        JsonMap.put(o, "process", process?.toJson())
        JsonMap.put(o, "seccomp", seccomp?.toJson())
        memoryPolicy?.let { JsonMap.put(o, "memoryPolicy", it.toJson()) }
        if (preserveFds > 0) JsonMap.put(o, "preserveFds", preserveFds)
        if (noNewKeyring) JsonMap.put(o, "noNewKeyring", true)
        return o
    }

    companion object {
        fun fromJson(node: Any?): ExecPayload? {
            if (node == null) return null
            val o = JsonMap.asObject(node) ?: return null
            return ExecPayload().apply {
                containerId = JsonMap.str(o, "containerId")
                bundle = JsonMap.str(o, "bundle")
                ociVersion = JsonMap.str(o, "ociVersion")
                process = Spec.Process.fromJson(o["process"])
                seccomp = Spec.LinuxSeccomp.fromJson(o["seccomp"])
                memoryPolicy = Spec.MemoryPolicy.fromJson(o["memoryPolicy"])
                preserveFds = JsonMap.intOr(o, "preserveFds", 0)
                noNewKeyring = JsonMap.boolOr(o, "noNewKeyring", false)
            }
        }
    }
}
