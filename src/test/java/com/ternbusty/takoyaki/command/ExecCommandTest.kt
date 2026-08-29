package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.util.JsonCodec
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class ExecCommandTest {

    companion object {
        private fun baseProcess(): Process = JsonCodec.decode<Process>(
            """
            {
              "args": ["init-cmd"],
              "env": ["PATH=/usr/bin", "FOO=bar"],
              "cwd": "/srv",
              "noNewPrivileges": true,
              "user": { "uid": 1000, "gid": 1000, "additionalGids": [5] },
              "capabilities": { "bounding": ["CAP_KILL"] },
              "apparmorProfile": "prof"
            }
            """.trimIndent()
        )
    }

    @Test
    fun commandReplacesArgsAndRestrictionsSurvive() {
        val p = ExecCommand.buildEffectiveProcess(
            baseProcess(), null, null, listOf(), listOf("sh", "-c", "id"),
            false, listOf(), listOf()
        )
        assertEquals(listOf("sh", "-c", "id"), p.args)
        // The security-relevant fields must ride along unchanged.
        assertEquals(true, p.noNewPrivileges)
        assertEquals(listOf("CAP_KILL"), p.capabilities!!.bounding)
        assertEquals("prof", p.apparmorProfile)
        assertEquals(1000u, p.user.uid)
        assertEquals("/srv", p.cwd)
    }

    @Test
    fun cliOverridesApplyOnTop() {
        val p = ExecCommand.buildEffectiveProcess(
            baseProcess(), "0:10", "/tmp", listOf("EXTRA=1"), listOf("id"),
            false, listOf(), listOf()
        )
        assertEquals(0u, p.user.uid)
        assertEquals(10u, p.user.gid)
        assertEquals(
            listOf(5u), p.user.additionalGids,
            "additionalGids from the spec must survive a -u override"
        )
        assertEquals("/tmp", p.cwd)
        assertEquals(listOf("PATH=/usr/bin", "FOO=bar", "EXTRA=1"), p.env)
    }

    @Test
    fun uidOnlyUserKeepsBaseGid() {
        val p = ExecCommand.buildEffectiveProcess(
            baseProcess(), "0", null, listOf(), listOf("id"),
            false, listOf(), listOf()
        )
        assertEquals(0u, p.user.uid)
        assertEquals(1000u, p.user.gid)
    }

    @Test
    fun baseIsNotMutated() {
        val base = baseProcess()
        ExecCommand.buildEffectiveProcess(
            base, "0:0", "/tmp",
            listOf("X=1"), listOf("other"),
            false, listOf(), listOf()
        )
        assertEquals(listOf("init-cmd"), base.args)
        assertEquals(1000u, base.user.uid)
        assertEquals(listOf("PATH=/usr/bin", "FOO=bar"), base.env)
    }

    @Test
    fun defaultEnvWhenSpecHasNone() {
        // When the spec has no env, buildEffectiveProcess returns an empty
        // list (HOME is added later by ExecProcess from /etc/passwd).
        val base = JsonCodec.decode<Process>(
            """{ "args": ["x"] }"""
        )
        val p = ExecCommand.buildEffectiveProcess(
            base, null, null, listOf(), listOf("id"),
            false, listOf(), listOf()
        )
        assertNotNull(p.env)
        assertTrue(p.env!!.isEmpty())
    }

    @Test
    fun rejectsMissingProcessSectionAndEmptyCommand() {
        assertThrows(IllegalArgumentException::class.java) {
            ExecCommand.buildEffectiveProcess(
                null, null, null, listOf(), listOf("id"),
                false, listOf(), listOf()
            )
        }

        val argless = JsonCodec.decode<Process>("""{"args":[]}""")
        assertThrows(IllegalArgumentException::class.java) {
            ExecCommand.buildEffectiveProcess(
                argless, null, null, listOf(), listOf(),
                false, listOf(), listOf()
            )
        }
    }

    @Test
    fun processFileIsExclusiveWithFlagOverrides() {
        assertNull(
            ExecCommand.exclusivityError(
                null, "0:0", "/tmp", listOf("X=1"), listOf("id")
            )
        )
        assertNull(
            ExecCommand.exclusivityError(
                "/p.json", null, null, listOf(), listOf()
            )
        )
        assertNotNull(
            ExecCommand.exclusivityError(
                "/p.json", "0:0", null, listOf(), listOf()
            )
        )
        assertNotNull(
            ExecCommand.exclusivityError(
                "/p.json", null, "/tmp", listOf(), listOf()
            )
        )
        assertNotNull(
            ExecCommand.exclusivityError(
                "/p.json", null, null, listOf("X=1"), listOf()
            )
        )
        assertNotNull(
            ExecCommand.exclusivityError(
                "/p.json", null, null, listOf(), listOf("id")
            )
        )
    }
}
