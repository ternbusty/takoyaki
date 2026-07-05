package com.ternbusty.takoyaki.contest;

import com.ternbusty.takoyaki.util.json.JsonWriter;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Test-side companion to the production runtime — youki calls this layer
 * {@code contest}. Each contest test drives the real {@code takoyaki} binary
 * end-to-end against a bundle laid down under a {@link org.junit.jupiter.api.io.TempDir}.
 *
 * Two prerequisites must hold for a contest test to run:
 *   1. {@code TAKOYAKI_BIN} environment variable points at the native binary.
 *   2. The host is Linux (clone3, unshare, cgroup v2).
 *
 * Annotate test classes with {@link RequiresTakoyaki @RequiresTakoyaki} to
 * have JUnit skip them otherwise (clean local-dev experience on macOS).
 */
public final class Contest {
    private Contest() {}

    /** Marker; combined with the {@link Condition} extension to gate execution. */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    @ExtendWith(Condition.class)
    public @interface RequiresTakoyaki {}

    /** Skip when prerequisites fail. */
    public static final class Condition implements ExecutionCondition {
        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext ctx) {
            String bin = System.getenv("TAKOYAKI_BIN");
            if (bin == null || bin.isBlank()) {
                return ConditionEvaluationResult.disabled(
                        "TAKOYAKI_BIN not set — skipping contest test");
            }
            String os = System.getProperty("os.name", "").toLowerCase();
            if (!os.contains("linux")) {
                return ConditionEvaluationResult.disabled(
                        "contest tests require Linux, got: " + os);
            }
            if (!java.nio.file.Files.isExecutable(java.nio.file.Path.of(bin))) {
                return ConditionEvaluationResult.disabled(
                        "TAKOYAKI_BIN is set but not executable: " + bin);
            }
            // Most contest specs unshare PID/MNT/IPC/UTS/NET — kernel requires
            // CAP_SYS_ADMIN unless a user namespace with mappings is in the
            // spec. Simpler to require effective uid 0. CI sudoes around it.
            if (!isRoot()) {
                return ConditionEvaluationResult.disabled(
                        "contest tests require root (or sudo); skipping");
            }
            return ConditionEvaluationResult.enabled("takoyaki binary available, running as root");
        }

        private static boolean isRoot() {
            try {
                Process p = new ProcessBuilder("id", "-u")
                        .redirectErrorStream(true).start();
                p.waitFor();
                String out = new String(p.getInputStream().readAllBytes()).trim();
                return "0".equals(out);
            } catch (Exception e) {
                return false;
            }
        }
    }

    // ---- bundle layout ------------------------------------------------------

    /** Path to the takoyaki binary under test, from TAKOYAKI_BIN. */
    public static String bin() {
        return System.getenv("TAKOYAKI_BIN");
    }

    /** Generate a fresh container id for one test. */
    public static String newContainerId() {
        return "contest-" + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Lay down a minimal OCI bundle at {@code bundle/}: empty rootfs dir +
     * config.json built from the supplied builder. The caller usually decides
     * to run {@code /bin/true} or similar; this helper just handles the boring
     * directory layout and JSON serialization.
     */
    public static Path writeBundle(Path bundle, Map<String, Object> spec) throws IOException {
        Files.createDirectories(bundle);
        Files.createDirectories(bundle.resolve("rootfs"));
        Path config = bundle.resolve("config.json");
        Files.writeString(config, JsonWriter.toPretty(spec));
        return bundle;
    }

    // ---- subprocess invocation ---------------------------------------------

    public record CmdResult(int rc, String stdout, String stderr) {
        public boolean ok() { return rc == 0; }
    }

    /** Run takoyaki with the given args + the standard --root path; returns rc, stdout, stderr. */
    public static CmdResult run(Path rootDir, String... args) throws IOException, InterruptedException {
        List<String> argv = new ArrayList<>();
        argv.add(bin());
        argv.add("--root");
        argv.add(rootDir.toString());
        for (String a : args) argv.add(a);

        // Redirect stdout/stderr to temp files, NOT to Java-owned pipes.
        //
        // takoyaki create forks an init grandchild that (correctly, per OCI)
        // inherits stdio and holds it until start+execve. If we used
        // ProcessBuilder's default pipe capture and then read from the pipe,
        // Process.getInputStream().readAllBytes() would block waiting for the
        // pipe's write side to fully close — which only happens after init
        // execs the workload or gets SIGKILL'd. On CI this manifested as the
        // contest task hitting its 15-minute timeout intermittently.
        //
        // Files give us:
        //   1. waitFor returns as soon as the create process itself exits;
        //   2. no pipe held by grandchild → nothing to block on;
        //   3. we can still read the captured output after waitFor.
        Path outFile = Files.createTempFile("takoyaki-stdout-", ".log");
        Path errFile = Files.createTempFile("takoyaki-stderr-", ".log");
        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectOutput(outFile.toFile());
        pb.redirectError(errFile.toFile());
        Process p = pb.start();
        try {
            // 30 s is generous — most contest steps finish in well under a second.
            if (!p.waitFor(30, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                throw new RuntimeException("takoyaki " + String.join(" ", args)
                        + " timed out after 30s");
            }
            String out = Files.readString(outFile);
            String err = Files.readString(errFile);
            return new CmdResult(p.exitValue(), out, err);
        } finally {
            Files.deleteIfExists(outFile);
            Files.deleteIfExists(errFile);
        }
    }

    // ---- busybox rootfs (for scenarios that actually start the container) --

    /**
     * Stage a minimal rootfs at {@code rootfs/} populated with busybox + a
     * few common applet symlinks (sh, sleep, true, false, cat, echo).
     *
     * Returns the absolute path to the rootfs on success. Returns {@code null}
     * if busybox can't be found on the host — callers should treat that as
     * "skip" via {@link org.junit.jupiter.api.Assumptions#assumeTrue}.
     *
     * busybox must be a fully static binary (no shared library dependencies)
     * because the container's rootfs has no /lib once we pivot into it. The
     * Debian/Ubuntu {@code busybox-static} package or the upstream prebuilt
     * binary both satisfy this.
     */
    public static Path stageBusyboxRootfs(Path rootfs) throws IOException {
        Path busybox = locateBusybox();
        if (busybox == null) return null;

        Path bin = rootfs.resolve("bin");
        Files.createDirectories(bin);
        Path bbCopy = bin.resolve("busybox");
        Files.copy(busybox, bbCopy, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        // chmod +x — Files.copy preserves mode on most filesystems but not all.
        bbCopy.toFile().setExecutable(true, false);

        for (String applet : List.of("sh", "sleep", "true", "false", "cat", "echo", "ls")) {
            Path link = bin.resolve(applet);
            try {
                Files.createSymbolicLink(link, Path.of("busybox"));
            } catch (java.nio.file.FileAlreadyExistsException ignored) {}
        }
        return rootfs;
    }

    private static Path locateBusybox() {
        // The container needs a STATIC busybox so it can run inside a rootfs
        // with no /lib mounted. Prefer the explicitly-static variant if it's
        // installed (apt-get install busybox-static), then fall back to the
        // regular path which is also static on Debian/Ubuntu.
        for (String candidate : List.of(
                "/bin/busybox-static",
                "/usr/bin/busybox-static",
                "/bin/busybox",
                "/usr/bin/busybox")) {
            Path p = Path.of(candidate);
            if (Files.isExecutable(p)) return p;
        }
        return null;
    }

    // ---- state polling -----------------------------------------------------

    /**
     * Poll {@code takoyaki state} until the JSON contains
     * {@code "status":"<expected>"} or until the deadline elapses. Returns
     * true if the expected status appears in time, false otherwise. Useful
     * for "after start, state must reflect running" assertions where the
     * state machine takes a tick or two to settle.
     */
    /**
     * Best-effort cleanup hook. Swallows all errors. Use in test {@code finally}
     * blocks so an assertion failure mid-test doesn't leak a running container
     * (which leaves a {@code takoyaki __init__} process holding the binary
     * file open and blocking the next {@code nativeCompile}).
     */
    public static void forceCleanup(Path rootDir, String id) {
        try { run(rootDir, "kill", id, "KILL"); } catch (Exception ignored) {}
        try { run(rootDir, "delete", "--force", id); } catch (Exception ignored) {}
    }

    public static boolean waitForStatus(Path rootDir, String id, String expected,
                                        long timeoutMs) throws IOException, InterruptedException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        // Match both "status":"running" AND "status" : "running" — Jackson's
        // pretty printer (default) inserts spaces around the colon, while
        // the compact form doesn't. Either is valid JSON.
        java.util.regex.Pattern pat = java.util.regex.Pattern.compile(
                "\"status\"\\s*:\\s*\"" + java.util.regex.Pattern.quote(expected) + "\"");
        while (System.nanoTime() < deadline) {
            CmdResult r = run(rootDir, "state", id);
            if (r.ok() && pat.matcher(r.stdout()).find()) return true;
            Thread.sleep(50);
        }
        return false;
    }
}
