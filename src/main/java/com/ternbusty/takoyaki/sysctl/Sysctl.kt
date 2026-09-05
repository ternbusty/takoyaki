package com.ternbusty.takoyaki.sysctl

import com.ternbusty.takoyaki.logger.Logger
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * Apply spec.linux.sysctl entries by writing to `/proc/sys/` paths.
 *
 * Only namespaced sysctls are allowed; anything else is rejected before the
 * write is attempted. This matches runc's behaviour and prevents a rootful
 * container init (which still holds CAP_SYS_ADMIN in the initial user
 * namespace at this point) from mutating host-global kernel state such as
 * kernel.core_pattern, kernel.modprobe, vm.*, etc.
 */
object Sysctl {

    fun apply(sysctls: Map<String, String>?) {
        if (sysctls.isNullOrEmpty()) return
        for ((key, value) in sysctls) {
            if (!isAllowed(key)) {
                Logger.warn("sysctl $key rejected: not a namespaced key")
                continue
            }
            val path = Path.of("/proc/sys/${key.replace('.', '/')}")
            try {
                Files.writeString(path, value)
                Logger.debug("sysctl $key=$value")
            } catch (ex: IOException) {
                Logger.warn("sysctl $key=$value failed: ${ex.message}")
            }
        }
    }

    /**
     * runc-compatible allowlist of sysctls that are safe to set from a
     * container init because the kernel scopes them per-namespace.
     *
     *   net.*                        network namespace
     *   kernel.hostname, .domainname UTS namespace
     *   kernel.msg*, .sem, .shm*     IPC namespace (SysV IPC limits)
     *   fs.mqueue.*                  IPC namespace (POSIX mqueue limits)
     *
     * Everything else (kernel.core_pattern, kernel.modprobe, vm.*, fs.*
     * outside of mqueue, etc.) touches host-global kernel state and is
     * refused.
     */
    private fun isAllowed(key: String): Boolean = when {
        key.startsWith("net.") -> true
        key.startsWith("fs.mqueue.") -> true
        key == "kernel.hostname" -> true
        key == "kernel.domainname" -> true
        key.startsWith("kernel.msg") -> true
        key == "kernel.sem" -> true
        key.startsWith("kernel.shm") -> true
        else -> false
    }
}
