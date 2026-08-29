package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.util.JsonCodec
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class ExecPayloadTest {

    @Test
    fun roundTripsAllFields() {
        val json = """
                {
                  "containerId": "c1",
                  "bundle": "/run/bundle",
                  "ociVersion": "1.2.0",
                  "process": {
                    "args": ["sh", "-c", "id"],
                    "cwd": "/tmp",
                    "noNewPrivileges": true,
                    "user": { "uid": 1000, "gid": 1000, "additionalGids": [10, 20] },
                    "capabilities": { "bounding": ["CAP_KILL"] },
                    "rlimits": [ { "type": "RLIMIT_NOFILE", "hard": 1024, "soft": 512 } ],
                    "apparmorProfile": "my-profile",
                    "oomScoreAdj": 100
                  },
                  "seccomp": {
                    "defaultAction": "SCMP_ACT_ERRNO",
                    "architectures": ["SCMP_ARCH_AARCH64"],
                    "syscalls": [ { "names": ["mkdir"], "action": "SCMP_ACT_ALLOW" } ],
                    "listenerPath": "/run/seccomp.sock"
                  }
                }
                """.trimIndent()
        val decoded = JsonCodec.decode<ExecPayload>(json)
        val p = JsonCodec.decode<ExecPayload>(JsonCodec.encode(decoded))

        assertEquals("c1", p.containerId)
        assertEquals("/run/bundle", p.bundle)
        assertEquals("1.2.0", p.ociVersion)
        assertEquals(listOf("sh", "-c", "id"), p.process!!.args)
        assertEquals("/tmp", p.process!!.cwd)
        assertEquals(true, p.process!!.noNewPrivileges)
        assertEquals(1000u, p.process!!.user.uid)
        assertEquals(listOf(10u, 20u), p.process!!.user.additionalGids)
        assertEquals(listOf("CAP_KILL"), p.process!!.capabilities!!.bounding)
        assertEquals("RLIMIT_NOFILE", p.process!!.rlimits!![0].type)
        assertEquals("my-profile", p.process!!.apparmorProfile)
        assertEquals(100, p.process!!.oomScoreAdj)
        assertEquals("SCMP_ACT_ERRNO", p.seccomp!!.defaultAction)
        assertEquals(listOf("mkdir"), p.seccomp!!.syscalls!![0].names)
        assertEquals("/run/seccomp.sock", p.seccomp!!.listenerPath)
    }

    @Test
    fun toleratesAbsentOptionalFields() {
        val p = JsonCodec.decode<ExecPayload>("""
                { "containerId": "c1" }
                """.trimIndent())
        assertEquals("c1", p.containerId)
        assertNull(p.process)
        assertNull(p.seccomp)

        val round = JsonCodec.decode<ExecPayload>(JsonCodec.encode(p))
        assertEquals("c1", round.containerId)
        assertNull(round.process)
    }
}
