package com.ternbusty.takoyaki.sysctl;

import com.ternbusty.takoyaki.logger.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Apply spec.linux.sysctl entries to /proc/sys/*.
 *
 * Only namespaced sysctls are allowed; anything else is rejected before the
 * write is attempted. This matches runc's behaviour and prevents a rootful
 * container init (which still holds CAP_SYS_ADMIN in the initial user
 * namespace at this point) from mutating host-global kernel state such as
 * kernel.core_pattern, kernel.modprobe, vm.*, etc.
 */
public final class Sysctl {
    private Sysctl() {}

    public static void apply(Map<String, String> sysctls) {
        if (sysctls == null || sysctls.isEmpty()) return;
        for (Map.Entry<String, String> e : sysctls.entrySet()) {
            String key = e.getKey();
            String value = e.getValue();
            if (!isAllowed(key)) {
                Logger.warn("sysctl " + key + " rejected: not a namespaced key");
                continue;
            }
            Path path = Path.of("/proc/sys/" + key.replace('.', '/'));
            try {
                Files.writeString(path, value);
                Logger.debug("sysctl " + key + "=" + value);
            } catch (IOException ex) {
                Logger.warn("sysctl " + key + "=" + value + " failed: " + ex.getMessage());
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
    private static boolean isAllowed(String key) {
        if (key.startsWith("net.")) return true;
        if (key.startsWith("fs.mqueue.")) return true;
        if (key.equals("kernel.hostname")) return true;
        if (key.equals("kernel.domainname")) return true;
        if (key.startsWith("kernel.msg")) return true;
        if (key.equals("kernel.sem")) return true;
        if (key.startsWith("kernel.shm")) return true;
        return false;
    }
}
