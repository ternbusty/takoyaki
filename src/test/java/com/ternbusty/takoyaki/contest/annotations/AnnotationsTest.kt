package com.ternbusty.takoyaki.contest.annotations

import com.ternbusty.takoyaki.contest.Contest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * spec.annotations is a free-form string -> string map containerd uses to
 * stash sandbox metadata (sandbox-id, image-name, k8s pod uid, ...). The OCI
 * spec REQUIRES the runtime to round-trip these into the state JSON so
 * the orchestrator can read them back.
 */
@Contest.RequiresTakoyaki
class AnnotationsTest {

    @Test
    fun annotationsRoundTripIntoStateOutput(@TempDir tmp: Path) {
        val rootDir = tmp.resolve("run")
        val bundle = tmp.resolve("bundle")

        // Three realistic keys: a containerd-style sandbox id, a dotted
        // domain-prefixed key (the OCI convention), and a value with a
        // colon and slash to make sure we're not breaking the JSON escape.
        Contest.writeBundle(bundle, mapOf(
            "ociVersion" to "1.0.0",
            "process" to mapOf(
                "terminal" to false,
                "args" to listOf("/bin/true"),
                "cwd" to "/",
                "user" to mapOf("uid" to 0, "gid" to 0)
            ),
            "root" to mapOf("path" to "rootfs"),
            "annotations" to mapOf(
                "io.containerd.sandbox.id" to "sandbox-abc123",
                "org.opencontainers.image.ref.name" to "docker.io/library/alpine:3.18",
                "io.kubernetes.pod.uid" to "pod-uid-99"
            ),
            "linux" to mapOf(
                "namespaces" to listOf(
                    mapOf("type" to "pid"),
                    mapOf("type" to "mount"),
                    mapOf("type" to "ipc"),
                    mapOf("type" to "uts"),
                    mapOf("type" to "cgroup")
                )
            )
        ))

        val id = Contest.newContainerId()
        val create = Contest.run(rootDir,
            "create", "--bundle", bundle.toString(), id)
        assertEquals(0, create.rc) { "create failed: ${create.stderr}" }

        val state = Contest.run(rootDir, "state", id)
        assertEquals(0, state.rc)
        val out = state.stdout

        // Each annotation must appear in the state output. We accept either
        // the canonical "annotations":{...} block or each key:value pair as
        // separate strings — the OCI spec doesn't pin the exact JSON shape
        // beyond "they round-trip".
        assertTrue(out.contains("sandbox-abc123")) {
            "annotation value 'sandbox-abc123' missing from state: $out"
        }
        assertTrue(out.contains("docker.io/library/alpine:3.18")) {
            "annotation with colon and slash missing: $out"
        }
        assertTrue(out.contains("pod-uid-99")) {
            "annotation value 'pod-uid-99' missing: $out"
        }

        Contest.run(rootDir, "delete", "--force", id)
    }
}
