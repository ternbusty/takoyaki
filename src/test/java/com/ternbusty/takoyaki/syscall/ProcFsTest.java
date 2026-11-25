package com.ternbusty.takoyaki.syscall;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ProcFs against the real /proc. A file mounted over a procfs file needs
 * privileges and is covered by the integration test instead.
 */
class ProcFsTest {

    @Test
    void writesThroughThreadSelf() throws Exception {
        String before = Files.readString(Path.of("/proc/thread-self/comm")).trim();
        try {
            ProcFs.write("thread-self/comm", "procfs-test");
            assertEquals("procfs-test", Files.readString(Path.of("/proc/thread-self/comm")).trim());
        } finally {
            ProcFs.write("thread-self/comm", before);
        }
    }

    @Test
    void existsFollowsSelfOnly() {
        assertTrue(ProcFs.exists("self/status"));
        assertTrue(ProcFs.exists("thread-self/attr/current") || !Files.exists(Path.of("/proc/self/attr")));
        assertFalse(ProcFs.exists("self/no-such-file"));
    }

    @Test
    void missingFileIsAnIOException() {
        assertThrows(IOException.class, () -> ProcFs.write("self/no-such-file", "x"));
    }

    @Test
    void symlinkOtherThanSelfIsRefused() {
        // /proc/self/cwd is a symlink beyond the leading "self": following it
        // would leave procfs.
        assertThrows(IllegalStateException.class, () -> ProcFs.exists("self/cwd/x"));
    }

    @Test
    void isProcfsTellsProcfsFromOtherFilesystems(@TempDir Path tmp) {
        assertTrue(ProcFs.isProcfs("/proc"));
        assertTrue(ProcFs.isProcfs("/proc/self/status"));
        assertFalse(ProcFs.isProcfs(tmp.toString()));
        assertFalse(ProcFs.isProcfs(tmp.resolve("missing").toString()));
    }
}
