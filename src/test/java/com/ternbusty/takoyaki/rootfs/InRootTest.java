package com.ternbusty.takoyaki.rootfs;

import com.ternbusty.takoyaki.syscall.PosixIO;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * InRoot against a real directory tree, with openat2 (true) and with the
 * fallback for kernels without it (false).
 */
class InRootTest {

    private static String real(Path p) throws Exception {
        return p.toRealPath().toString();
    }

    private static String pathOf(int fd) {
        assertTrue(fd >= 0, "expected an fd");
        String p = InRoot.realPath(fd);
        PosixIO.close(fd);
        return p;
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void opensAndCreatesInsideTheRootfs(boolean openat2, @TempDir Path tmp) throws Exception {
        Path rootfs = Files.createDirectory(tmp.resolve("rootfs"));
        Files.createDirectories(rootfs.resolve("etc"));
        try (InRoot root = InRoot.of(rootfs.toString(), openat2)) {
            assertEquals(real(rootfs) + "/etc", pathOf(root.open("/etc")));
            assertEquals(real(rootfs) + "/a/b/c", pathOf(root.mkdirAll("/a/b/c", 0755)));
            assertEquals(real(rootfs) + "/f/file", pathOf(root.createFile("/f/file", 0644)));
            assertTrue(Files.isRegularFile(rootfs.resolve("f/file")));
            // Existing ones are opened, not recreated.
            assertEquals(real(rootfs) + "/a/b/c", pathOf(root.mkdirAll("a/b/c", 0755)));
            assertEquals(real(rootfs) + "/f/file", pathOf(root.createFile("f/file", 0644)));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void missingPathFailsWithEnoent(boolean openat2, @TempDir Path tmp) throws Exception {
        Path rootfs = Files.createDirectory(tmp.resolve("rootfs"));
        try (InRoot root = InRoot.of(rootfs.toString(), openat2)) {
            assertEquals(-1, root.open("/nope"));
            assertEquals(com.ternbusty.takoyaki.syscall.Constants.ENOENT, root.errno());
        }
    }

    /**
     * A symlink in the rootfs that points outside it, as a process sharing a
     * volume with the rootfs could swap in: it resolves inside the rootfs, as
     * it would for the container, and if it leads nowhere there the call
     * fails instead of following it out. Without openat2 InRoot resolves it
     * itself and must give the same results.
     */
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void symlinkOutOfTheRootfsResolvesInside(boolean openat2, @TempDir Path tmp) throws Exception {
        Path rootfs = Files.createDirectory(tmp.resolve("rootfs"));
        Path outside = Files.createDirectory(tmp.resolve("outside"));
        Files.createSymbolicLink(rootfs.resolve("abs"), outside);
        Files.createSymbolicLink(rootfs.resolve("rel"), Path.of("../../outside"));
        // Where abs points to, seen from inside the rootfs.
        Files.createDirectories(Path.of(rootfs + outside.toString()));
        try (InRoot root = InRoot.of(rootfs.toString(), openat2)) {
            assertEquals(real(rootfs) + outside + "/x", pathOf(root.mkdirAll("/abs/x", 0755)));
            assertEquals(real(rootfs) + outside + "/file", pathOf(root.createFile("/abs/file", 0644)));
            assertEquals(real(rootfs), pathOf(root.open("/../../..")));
            // rel leads to <rootfs>/outside, which does not exist.
            assertEquals(-1, root.mkdirAll("/rel/y", 0755));
            assertEquals(com.ternbusty.takoyaki.syscall.Constants.ENOENT, root.errno());
        }
        try (var entries = Files.list(outside)) {
            assertEquals(0, entries.count(), "nothing may be created outside the rootfs");
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void symlinkLoopFailsWithEloop(boolean openat2, @TempDir Path tmp) throws Exception {
        Path rootfs = Files.createDirectory(tmp.resolve("rootfs"));
        Files.createSymbolicLink(rootfs.resolve("a"), Path.of("b"));
        Files.createSymbolicLink(rootfs.resolve("b"), Path.of("a"));
        try (InRoot root = InRoot.of(rootfs.toString(), openat2)) {
            assertEquals(-1, root.open("/a/x"));
            assertEquals(com.ternbusty.takoyaki.syscall.Constants.ELOOP, root.errno());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void isSymlinkDoesNotFollowTheLastComponent(boolean openat2, @TempDir Path tmp) throws Exception {
        Path rootfs = Files.createDirectory(tmp.resolve("rootfs"));
        Files.createDirectory(rootfs.resolve("dir"));
        Files.createSymbolicLink(rootfs.resolve("link"), Path.of("dir"));
        try (InRoot root = InRoot.of(rootfs.toString(), openat2)) {
            assertTrue(root.isSymlink("/link"));
            assertFalse(root.isSymlink("/dir"));
            assertFalse(root.isSymlink("/missing"));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void reopenAfterMountGivesTheSamePath(boolean openat2, @TempDir Path tmp) throws Exception {
        Path rootfs = Files.createDirectory(tmp.resolve("rootfs"));
        try (InRoot root = InRoot.of(rootfs.toString(), openat2)) {
            int fd = root.mkdirAll("/mnt", 0755);
            assertEquals(real(rootfs) + "/mnt", pathOf(root.reopenAfterMount(fd)));
            PosixIO.close(fd);
        }
    }
}
