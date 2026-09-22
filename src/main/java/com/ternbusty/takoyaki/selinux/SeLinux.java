package com.ternbusty.takoyaki.selinux;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.nio.charset.StandardCharsets;
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

    private static final int O_WRONLY = NativeH.O_WRONLY();
    private static final int O_CLOEXEC = NativeH.O_CLOEXEC();

    private static boolean writeProcAttr(String path, byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            int fd = PosixIO.open(arena, path, O_WRONLY | O_CLOEXEC, 0);
            if (fd < 0) {
                Logger.warn("selinux open " + path + " failed: " + Libc.strerror(Libc.errno()));
                return false;
            }
            try {
                var buf = arena.allocate(data.length);
                buf.copyFrom(java.lang.foreign.MemorySegment.ofArray(data));
                long n = NativeH.write(fd, buf, data.length);
                if (n < 0) {
                    Logger.warn("selinux write " + path + " failed: " + Libc.strerror(Libc.errno()));
                    return false;
                }
                return true;
            } finally {
                NativeH.close(fd);
            }
        }
    }

    public static void apply(String label) {
        if (label == null || label.isEmpty()) return;
        if (!Files.exists(Path.of("/sys/fs/selinux")) && !Files.exists(Path.of("/sys/fs/selinuxfs"))) {
            Logger.debug("selinux not enabled, skipping label=" + label);
            return;
        }
        if (writeProcAttr("/proc/self/attr/exec", label.getBytes(StandardCharsets.UTF_8))) {
            Logger.debug("selinux exec label staged: " + label);
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
        if (writeProcAttr("/proc/self/attr/keycreate", label.getBytes(StandardCharsets.UTF_8))) {
            Logger.debug("selinux keycreate label set: " + label);
        }
    }

    /**
     * Clear the keycreate label so later key operations do not inherit the
     * override. Writing an empty string resets to the default.
     */
    public static void clearKeyCreate() {
        if (!Files.exists(Path.of("/proc/self/attr/keycreate"))) return;
        writeProcAttr("/proc/self/attr/keycreate", new byte[0]);
    }
}
