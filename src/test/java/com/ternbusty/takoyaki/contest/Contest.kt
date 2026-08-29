package com.ternbusty.takoyaki.contest

import com.ternbusty.takoyaki.util.json.JsonWriter
import org.junit.jupiter.api.extension.ConditionEvaluationResult
import org.junit.jupiter.api.extension.ExecutionCondition
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.extension.ExtensionContext
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

/**
 * Test-side companion to the production runtime — youki calls this layer
 * `contest`. Each contest test drives the real `takoyaki` binary
 * end-to-end against a bundle laid down under a [org.junit.jupiter.api.io.TempDir].
 *
 * Two prerequisites must hold for a contest test to run:
 *   1. `TAKOYAKI_BIN` environment variable points at the native binary.
 *   2. The host is Linux (clone3, unshare, cgroup v2).
 *
 * Annotate test classes with [RequiresTakoyaki] to
 * have JUnit skip them otherwise (clean local-dev experience on macOS).
 */
object Contest {

    /** Marker; combined with the [Condition] extension to gate execution. */
    @Retention(AnnotationRetention.RUNTIME)
    @Target(AnnotationTarget.CLASS)
    @ExtendWith(Condition::class)
    annotation class RequiresTakoyaki

    /** Skip when prerequisites fail. */
    class Condition : ExecutionCondition {
        override fun evaluateExecutionCondition(ctx: ExtensionContext): ConditionEvaluationResult {
            val bin = System.getenv("TAKOYAKI_BIN")
            if (bin.isNullOrBlank()) {
                return ConditionEvaluationResult.disabled(
                    "TAKOYAKI_BIN not set — skipping contest test"
                )
            }
            val os = System.getProperty("os.name", "").lowercase()
            if ("linux" !in os) {
                return ConditionEvaluationResult.disabled(
                    "contest tests require Linux, got: $os"
                )
            }
            if (!Files.isExecutable(Path.of(bin))) {
                return ConditionEvaluationResult.disabled(
                    "TAKOYAKI_BIN is set but not executable: $bin"
                )
            }
            // Most contest specs unshare PID/MNT/IPC/UTS/NET — kernel requires
            // CAP_SYS_ADMIN unless a user namespace with mappings is in the
            // spec. Simpler to require effective uid 0. CI sudoes around it.
            if (!isRoot()) {
                return ConditionEvaluationResult.disabled(
                    "contest tests require root (or sudo); skipping"
                )
            }
            return ConditionEvaluationResult.enabled("takoyaki binary available, running as root")
        }

        companion object {
            private fun isRoot(): Boolean {
                return try {
                    val p = ProcessBuilder("id", "-u")
                        .redirectErrorStream(true).start()
                    p.waitFor()
                    val out = String(p.inputStream.readAllBytes()).trim()
                    out == "0"
                } catch (_: Exception) {
                    false
                }
            }
        }
    }

    // ---- bundle layout ------------------------------------------------------

    /** Path to the takoyaki binary under test, from TAKOYAKI_BIN. */
    fun bin(): String = System.getenv("TAKOYAKI_BIN")

    /** Generate a fresh container id for one test. */
    fun newContainerId(): String = "contest-" + UUID.randomUUID().toString().substring(0, 8)

    /**
     * Lay down a minimal OCI bundle at `bundle/`: empty rootfs dir +
     * config.json built from the supplied builder. The caller usually decides
     * to run `/bin/true` or similar; this helper just handles the boring
     * directory layout and JSON serialization.
     */
    @Throws(IOException::class)
    fun writeBundle(bundle: Path, spec: Map<String, Any>): Path {
        Files.createDirectories(bundle)
        Files.createDirectories(bundle.resolve("rootfs"))
        val config = bundle.resolve("config.json")
        Files.writeString(config, JsonWriter.toPretty(spec))
        return bundle
    }

    // ---- subprocess invocation ---------------------------------------------

    data class CmdResult(val rc: Int, val stdout: String, val stderr: String) {
        fun ok(): Boolean = rc == 0
    }

    /** Run takoyaki with the given args + the standard --root path; returns rc, stdout, stderr. */
    @Throws(IOException::class, InterruptedException::class)
    fun run(rootDir: Path, vararg args: String): CmdResult {
        val argv = mutableListOf<String>()
        argv.add(bin())
        argv.add("--root")
        argv.add(rootDir.toString())
        for (a in args) argv.add(a)

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
        //   2. no pipe held by grandchild -> nothing to block on;
        //   3. we can still read the captured output after waitFor.
        val outFile = Files.createTempFile("takoyaki-stdout-", ".log")
        val errFile = Files.createTempFile("takoyaki-stderr-", ".log")
        val pb = ProcessBuilder(argv)
        pb.redirectOutput(outFile.toFile())
        pb.redirectError(errFile.toFile())
        val p = pb.start()
        try {
            // 30 s is generous — most contest steps finish in well under a second.
            if (!p.waitFor(30, TimeUnit.SECONDS)) {
                p.destroyForcibly()
                throw RuntimeException(
                    "takoyaki ${args.joinToString(" ")} timed out after 30s"
                )
            }
            val out = Files.readString(outFile)
            val err = Files.readString(errFile)
            return CmdResult(p.exitValue(), out, err)
        } finally {
            Files.deleteIfExists(outFile)
            Files.deleteIfExists(errFile)
        }
    }

    // ---- busybox rootfs (for scenarios that actually start the container) --

    /**
     * Stage a minimal rootfs at `rootfs/` populated with busybox + a
     * few common applet symlinks (sh, sleep, true, false, cat, echo).
     *
     * Returns the absolute path to the rootfs on success. Returns `null`
     * if busybox can't be found on the host — callers should treat that as
     * "skip" via [org.junit.jupiter.api.Assumptions.assumeTrue].
     *
     * busybox must be a fully static binary (no shared library dependencies)
     * because the container's rootfs has no /lib once we pivot into it. The
     * Debian/Ubuntu `busybox-static` package or the upstream prebuilt
     * binary both satisfy this.
     */
    @Throws(IOException::class)
    fun stageBusyboxRootfs(rootfs: Path): Path? {
        val busybox = locateBusybox() ?: return null

        val bin = rootfs.resolve("bin")
        Files.createDirectories(bin)
        val bbCopy = bin.resolve("busybox")
        Files.copy(busybox, bbCopy, StandardCopyOption.REPLACE_EXISTING)
        // chmod +x — Files.copy preserves mode on most filesystems but not all.
        bbCopy.toFile().setExecutable(true, false)

        for (applet in listOf("sh", "sleep", "true", "false", "cat", "echo", "ls")) {
            val link = bin.resolve(applet)
            try {
                Files.createSymbolicLink(link, Path.of("busybox"))
            } catch (_: java.nio.file.FileAlreadyExistsException) {
            }
        }
        return rootfs
    }

    private fun locateBusybox(): Path? {
        // The container needs a STATIC busybox so it can run inside a rootfs
        // with no /lib mounted. Prefer the explicitly-static variant if it's
        // installed (apt-get install busybox-static), then fall back to the
        // regular path which is also static on Debian/Ubuntu.
        for (candidate in listOf(
            "/bin/busybox-static",
            "/usr/bin/busybox-static",
            "/bin/busybox",
            "/usr/bin/busybox"
        )) {
            val p = Path.of(candidate)
            if (Files.isExecutable(p)) return p
        }
        return null
    }

    // ---- state polling -----------------------------------------------------

    /**
     * Best-effort cleanup hook. Swallows all errors. Use in test `finally`
     * blocks so an assertion failure mid-test doesn't leak a running container
     * (which leaves a `takoyaki __init__` process holding the binary
     * file open and blocking the next `nativeCompile`).
     */
    fun forceCleanup(rootDir: Path, id: String) {
        try { run(rootDir, "kill", id, "KILL") } catch (_: Exception) {}
        try { run(rootDir, "delete", "--force", id) } catch (_: Exception) {}
    }

    /**
     * Poll `takoyaki state` until the JSON contains
     * `"status":"<expected>"` or until the deadline elapses. Returns
     * true if the expected status appears in time, false otherwise. Useful
     * for "after start, state must reflect running" assertions where the
     * state machine takes a tick or two to settle.
     */
    @Throws(IOException::class, InterruptedException::class)
    fun waitForStatus(
        rootDir: Path, id: String, expected: String,
        timeoutMs: Long
    ): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000L
        // Match both "status":"running" AND "status" : "running" — Jackson's
        // pretty printer (default) inserts spaces around the colon, while
        // the compact form doesn't. Either is valid JSON.
        val pat = Pattern.compile(
            "\"status\"\\s*:\\s*\"" + Pattern.quote(expected) + "\""
        )
        while (System.nanoTime() < deadline) {
            val r = run(rootDir, "state", id)
            if (r.ok() && pat.matcher(r.stdout).find()) return true
            Thread.sleep(50)
        }
        return false
    }
}
