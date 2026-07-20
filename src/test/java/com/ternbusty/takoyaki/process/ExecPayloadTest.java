package com.ternbusty.takoyaki.process;

import com.ternbusty.takoyaki.util.Json;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ExecPayloadTest {

    @Test
    void roundTripsAllFields() {
        String json = """
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
                """;
        ExecPayload decoded = Json.decode(json, ExecPayload::fromJson);
        ExecPayload p = Json.decode(Json.encode(decoded.toJson()), ExecPayload::fromJson);

        assertEquals("c1", p.containerId);
        assertEquals("/run/bundle", p.bundle);
        assertEquals("1.2.0", p.ociVersion);
        assertEquals(List.of("sh", "-c", "id"), p.process.args);
        assertEquals("/tmp", p.process.cwd);
        assertEquals(Boolean.TRUE, p.process.noNewPrivileges);
        assertEquals(1000, p.process.user.uid);
        assertEquals(List.of(10, 20), p.process.user.additionalGids);
        assertEquals(List.of("CAP_KILL"), p.process.capabilities.bounding);
        assertEquals("RLIMIT_NOFILE", p.process.rlimits.get(0).type);
        assertEquals("my-profile", p.process.apparmorProfile);
        assertEquals(100, p.process.oomScoreAdj);
        assertEquals("SCMP_ACT_ERRNO", p.seccomp.defaultAction);
        assertEquals(List.of("mkdir"), p.seccomp.syscalls.get(0).names);
        assertEquals("/run/seccomp.sock", p.seccomp.listenerPath);
    }

    @Test
    void toleratesAbsentOptionalFields() {
        ExecPayload p = Json.decode("""
                { "containerId": "c1" }
                """, ExecPayload::fromJson);
        assertEquals("c1", p.containerId);
        assertNull(p.process);
        assertNull(p.seccomp);

        ExecPayload round = Json.decode(Json.encode(p.toJson()), ExecPayload::fromJson);
        assertEquals("c1", round.containerId);
        assertNull(round.process);
    }
}
