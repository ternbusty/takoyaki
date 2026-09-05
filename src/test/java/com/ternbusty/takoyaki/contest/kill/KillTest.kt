package com.ternbusty.takoyaki.contest.kill

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Exercises the `kill` subcommand at the binary surface.
 *
 * Two scenarios that don't need a real rootfs to validate:
 *   - kill on a container id that was never created returns non-zero
 *   - kill accepts the OCI signal name forms (numeric, SIGTERM, TERM)
 *
 * Full SIGTERM-induces-stopped lifecycle needs a real busybox rootfs and
 * a long-running init process. That lives in the runtime-tools validation
 * suite (lifecycle and killsig tests).
 */
@Contest.RequiresTakoyaki
class KillTest {

    @Test
    fun killOnUnknownContainerReturnsNonzero(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")

        // The runtime must report "no such container" via a non-zero exit
        // code. A 0 exit would let orchestrators believe they killed it
        // and proceed to delete, which would itself fail mysteriously.
        val r = Contest.run(rootDir, "kill", "never-existed", "TERM")
        assertNotEquals(0, r.rc) {
            "kill on a never-created container must return non-zero. " +
                "stdout=<${r.stdout}> stderr=<${r.stderr}>"
        }
    }

    @Test
    fun killAcceptsNumericSignal(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        // Numeric signal form. 15 = SIGTERM. Should fail because the
        // container doesn't exist, but MUST fail with "no such container"
        // not "invalid signal" — the parser must accept the number first.
        val r = Contest.run(rootDir, "kill", "never-existed", "15")
        assertNotEquals(0, r.rc)
        assertFalse(r.stderr.lowercase().contains("invalid signal")) {
            "numeric signal '15' must parse as SIGTERM, not 'invalid signal'. " +
                "stderr=<${r.stderr}>"
        }
    }

    @Test
    fun killAcceptsBareSignalNameWithoutSigPrefix(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        // "TERM" must be accepted as equivalent to "SIGTERM". A KillCommand
        // bug at one point case-rejected this; runtime-tools uses both forms
        // depending on the test.
        val r = Contest.run(rootDir, "kill", "never-existed", "TERM")
        assertNotEquals(0, r.rc)
        assertFalse(r.stderr.lowercase().contains("invalid signal")) {
            "bare 'TERM' must parse to SIGTERM, not be rejected. " +
                "stderr=<${r.stderr}>"
        }
    }

    @Test
    fun killRejectsTotallyUnknownSignalName(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        // A garbage signal name MUST be rejected at parse time. The error
        // surface for "bad signal name" should not look like the error
        // surface for "no such container" — the user needs to be able to
        // tell what went wrong.
        val r = Contest.run(rootDir, "kill", "never-existed", "NOT_A_REAL_SIGNAL")
        assertNotEquals(0, r.rc)
        // We don't pin the exact wording but we want SOMETHING signal-related.
        val lc = r.stderr.lowercase()
        assertTrue(lc.contains("signal") || lc.contains("invalid")) {
            "kill must report a signal-related error for bogus signal. stderr=<${r.stderr}>"
        }
    }
}
