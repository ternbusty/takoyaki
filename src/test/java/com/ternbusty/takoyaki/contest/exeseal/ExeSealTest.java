package com.ternbusty.takoyaki.contest.exeseal;

import com.ternbusty.takoyaki.contest.Contest;
import com.ternbusty.takoyaki.contest.Contest.CmdResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verify CVE-2019-5736 mitigation: ExeSeal.cloneSelfExe must succeed during
 * container creation. If it fails, CreateCommand returns non-zero with a
 * "CVE-2019-5736" error message.
 *
 * This is an end-to-end gate: if create succeeds, the sealed fd was
 * successfully produced (overlayfs or memfd) and the child was exec'd through
 * /proc/self/fd/N rather than the on-disk binary.
 */
@Contest.RequiresTakoyaki
class ExeSealTest {

    @Test
    void createSucceedsWithExeSeal(@TempDir Path tmp) throws Exception {
        Path rootDir = tmp.resolve("run");
        Path bundle = tmp.resolve("bundle");

        Contest.writeBundle(bundle, Map.of(
                "ociVersion", "1.0.0",
                "process", Map.of(
                        "terminal", false,
                        "args", List.of("/bin/true"),
                        "cwd", "/",
                        "user", Map.of("uid", 0, "gid", 0)
                ),
                "root", Map.of("path", "rootfs"),
                "linux", Map.of(
                        "namespaces", List.of(
                                Map.of("type", "pid"),
                                Map.of("type", "mount"),
                                Map.of("type", "ipc"),
                                Map.of("type", "uts"),
                                Map.of("type", "cgroup")
                        )
                )
        ));

        String id = Contest.newContainerId();

        CmdResult create = Contest.run(rootDir,
                "create", "--bundle", bundle.toString(), id);
        assertEquals(0, create.rc(),
                () -> "create with exe-seal failed: " + create.stderr());
        assertFalse(create.stderr().contains("CVE-2019-5736"),
                "exe-seal should not report failure");

        try {
            CmdResult state = Contest.run(rootDir, "state", id);
            assertTrue(state.stdout().contains("\"status\""),
                    () -> "state should return valid JSON: " + state.stdout());
        } finally {
            Contest.forceCleanup(rootDir, id);
        }
    }
}
