package com.ternbusty.takoyaki.selinux;

import com.ternbusty.takoyaki.logger.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Apply a SELinux exec context to the current thread.
 *
 *   echo "container_t:s0:c1,c2" > /proc/self/attr/exec
 *
 * The next exec(2) loads the process with that label. Like AppArmor, the kernel
 * rejects further label changes after exec when PR_SET_NO_NEW_PRIVS is set, so we
 * must do this before seccomp + execvp.
 */
public final class SeLinux {
    private SeLinux() {}

    public static void apply(String label) {
        if (label == null || label.isEmpty()) return;
        if (!Files.exists(Path.of("/sys/fs/selinux")) && !Files.exists(Path.of("/sys/fs/selinuxfs"))) {
            Logger.debug("selinux not enabled, skipping label=" + label);
            return;
        }
        try {
            Files.writeString(Path.of("/proc/self/attr/exec"), label);
            Logger.debug("selinux exec label staged: " + label);
        } catch (IOException e) {
            Logger.warn("selinux exec label write failed (label=" + label + "): " + e.getMessage());
        }
    }

    /**
     * Write the SELinux keycreate label so that subsequently created kernel
     * keys (e.g. session keyrings) inherit the container's label instead of
     * the runtime's. No-op when label is null/empty or SELinux is off.
     */
    public static void applyKeyCreate(String label) {
        if (label == null || label.isEmpty()) return;
        if (!Files.exists(Path.of("/proc/self/attr/keycreate"))) return;
        try {
            Files.writeString(Path.of("/proc/self/attr/keycreate"), label);
            Logger.debug("selinux keycreate label set: " + label);
        } catch (IOException e) {
            Logger.warn("selinux keycreate label write failed (label=" + label + "): "
                    + e.getMessage());
        }
    }

    /**
     * Clear the keycreate label so later key operations do not inherit the
     * override. Writing an empty string resets to the default.
     */
    public static void clearKeyCreate() {
        Path p = Path.of("/proc/self/attr/keycreate");
        if (!Files.exists(p)) return;
        try {
            Files.writeString(p, "");
        } catch (IOException ignored) {
            // Best effort: clearing may fail if SELinux is not active.
        }
    }
}
