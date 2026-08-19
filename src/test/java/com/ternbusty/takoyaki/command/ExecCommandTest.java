package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.util.Json;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExecCommandTest {

    private static Spec.Process baseProcess() {
        return Json.decode("""
                {
                  "args": ["init-cmd"],
                  "env": ["PATH=/usr/bin", "FOO=bar"],
                  "cwd": "/srv",
                  "noNewPrivileges": true,
                  "user": { "uid": 1000, "gid": 1000, "additionalGids": [5] },
                  "capabilities": { "bounding": ["CAP_KILL"] },
                  "apparmorProfile": "prof"
                }
                """, Spec.Process::fromJson);
    }

    @Test
    void commandReplacesArgsAndRestrictionsSurvive() {
        Spec.Process p = ExecCommand.buildEffectiveProcess(
                baseProcess(), null, null, List.of(), List.of("sh", "-c", "id"),
                false, List.of(), List.of());
        assertEquals(List.of("sh", "-c", "id"), p.args);
        // The security-relevant fields must ride along unchanged.
        assertEquals(Boolean.TRUE, p.noNewPrivileges);
        assertEquals(List.of("CAP_KILL"), p.capabilities.bounding);
        assertEquals("prof", p.apparmorProfile);
        assertEquals(1000, p.user.uid);
        assertEquals("/srv", p.cwd);
    }

    @Test
    void cliOverridesApplyOnTop() {
        Spec.Process p = ExecCommand.buildEffectiveProcess(
                baseProcess(), "0:10", "/tmp", List.of("EXTRA=1"), List.of("id"),
                false, List.of(), List.of());
        assertEquals(0, p.user.uid);
        assertEquals(10, p.user.gid);
        assertEquals(List.of(5), p.user.additionalGids,
                "additionalGids from the spec must survive a -u override");
        assertEquals("/tmp", p.cwd);
        assertEquals(List.of("PATH=/usr/bin", "FOO=bar", "EXTRA=1"), p.env);
    }

    @Test
    void uidOnlyUserKeepsBaseGid() {
        Spec.Process p = ExecCommand.buildEffectiveProcess(
                baseProcess(), "0", null, List.of(), List.of("id"),
                false, List.of(), List.of());
        assertEquals(0, p.user.uid);
        assertEquals(1000, p.user.gid);
    }

    @Test
    void baseIsNotMutated() {
        Spec.Process base = baseProcess();
        ExecCommand.buildEffectiveProcess(base, "0:0", "/tmp",
                List.of("X=1"), List.of("other"),
                false, List.of(), List.of());
        assertEquals(List.of("init-cmd"), base.args);
        assertEquals(1000, base.user.uid);
        assertEquals(List.of("PATH=/usr/bin", "FOO=bar"), base.env);
    }

    @Test
    void defaultEnvWhenSpecHasNone() {
        Spec.Process base = Json.decode("""
                { "args": ["x"] }
                """, Spec.Process::fromJson);
        Spec.Process p = ExecCommand.buildEffectiveProcess(
                base, null, null, List.of(), List.of("id"),
                false, List.of(), List.of());
        assertTrue(p.env.stream().anyMatch(e -> e.startsWith("PATH=")));
    }

    @Test
    void rejectsMissingProcessSectionAndEmptyCommand() {
        assertThrows(IllegalArgumentException.class, () ->
                ExecCommand.buildEffectiveProcess(null, null, null, List.of(), List.of("id"),
                        false, List.of(), List.of()));

        Spec.Process argless = Json.decode("{}", Spec.Process::fromJson);
        assertThrows(IllegalArgumentException.class, () ->
                ExecCommand.buildEffectiveProcess(argless, null, null, List.of(), List.of(),
                        false, List.of(), List.of()));
    }

    @Test
    void processFileIsExclusiveWithFlagOverrides() {
        assertNull(ExecCommand.exclusivityError(null, "0:0", "/tmp",
                List.of("X=1"), List.of("id")));
        assertNull(ExecCommand.exclusivityError("/p.json", null, null,
                List.of(), List.of()));
        assertNotNull(ExecCommand.exclusivityError("/p.json", "0:0", null,
                List.of(), List.of()));
        assertNotNull(ExecCommand.exclusivityError("/p.json", null, "/tmp",
                List.of(), List.of()));
        assertNotNull(ExecCommand.exclusivityError("/p.json", null, null,
                List.of("X=1"), List.of()));
        assertNotNull(ExecCommand.exclusivityError("/p.json", null, null,
                List.of(), List.of("id")));
    }
}
