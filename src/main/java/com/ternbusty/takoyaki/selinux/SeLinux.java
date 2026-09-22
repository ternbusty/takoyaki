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
                System.err.println("[kc-diag] open FAIL path=" + path
                        + " errno=" + err + " " + Libc.strerror(err));
                return false;
            }
            try {
                var buf = arena.allocate(data.length);
                buf.copyFrom(java.lang.foreign.MemorySegment.ofArray(data));
                long n = NativeH.write(fd, buf, data.length);
                if (n < 0) {
                    int err = Libc.errno();
                    System.err.println("[kc-diag] write FAIL path=" + path
                            + " fd=" + fd + " len=" + data.length
                            + " errno=" + err + " " + Libc.strerror(err)
                            + " n=" + n);
                    return false;
                }
                System.err.println("[kc-diag] write OK path=" + path
                        + " fd=" + fd + " n=" + n);
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
        if (label == null || label.isEmpty()) return;
        if (!Files.exists(Path.of("/proc/self/attr/keycreate"))) return;
        byte[] data = label.getBytes(StandardCharsets.UTF_8);
        if (writeProcAttr("/proc/self/attr/keycreate", data)) {
            Logger.debug("selinux keycreate label set: " + label);
            return;
        }
        // FFM write failed — try FileOutputStream as fallback
        try (var fos = new java.io.FileOutputStream("/proc/self/attr/keycreate")) {
            fos.write(data);
            System.err.println("[kc-diag] NIO fallback OK");
            Logger.debug("selinux keycreate label set (nio): " + label);
        } catch (Exception e) {
            System.err.println("[kc-diag] NIO fallback FAIL: " + e);
        }
    }

    public static void clearKeyCreate() {
        if (!Files.exists(Path.of("/proc/self/attr/keycreate"))) return;
        writeProcAttr("/proc/self/attr/keycreate", new byte[0]);
    }
}
