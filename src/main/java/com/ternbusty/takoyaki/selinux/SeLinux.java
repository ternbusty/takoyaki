package com.ternbusty.takoyaki.selinux;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.lang.foreign.Arena;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class SeLinux {
    private SeLinux() {}

    private static final int O_WRONLY = NativeH.O_WRONLY();
    private static final int O_CLOEXEC = NativeH.O_CLOEXEC();

    private static boolean writeProcAttr(String path, byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            int fd = PosixIO.open(arena, path, O_WRONLY | O_CLOEXEC, 0);
            if (fd < 0) {
                int err = Libc.errno();
                Logger.warn("selinux open " + path + " failed (errno=" + err + "): "
                        + Libc.strerror(err));
                return false;
            }
            try {
                var buf = arena.allocate(data.length);
                buf.copyFrom(java.lang.foreign.MemorySegment.ofArray(data));
                long n = NativeH.write(fd, buf, data.length);
                if (n < 0) {
                    int err = Libc.errno();
                    Logger.warn("selinux write " + path + " failed (errno=" + err + "): "
                            + Libc.strerror(err));
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

    public static void applyKeyCreate(String label) {
        if (label == null || label.isEmpty()) {
            System.err.println("[kc-diag] skip label=" + label);
            return;
        }
        boolean exists = Files.exists(Path.of("/proc/self/attr/keycreate"));
        System.err.println("[kc-diag] label=" + label + " exists=" + exists);
        if (!exists) return;
        byte[] data = label.getBytes(StandardCharsets.UTF_8);
        boolean ok = writeProcAttr("/proc/self/attr/keycreate", data);
        System.err.println("[kc-diag] write ok=" + ok);
        if (ok) {
            Logger.debug("selinux keycreate label set: " + label);
        }
    }

    public static void clearKeyCreate() {
        if (!Files.exists(Path.of("/proc/self/attr/keycreate"))) return;
        writeProcAttr("/proc/self/attr/keycreate", new byte[0]);
    }
}
