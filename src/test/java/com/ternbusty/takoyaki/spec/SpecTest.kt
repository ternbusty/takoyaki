package com.ternbusty.takoyaki.spec

import com.ternbusty.takoyaki.util.Json
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class SpecTest {

    @Test
    fun decodeMinimalSpec() {
        // Smallest config.json we accept: ociVersion + root + process.
        val json = """
                {
                  "ociVersion": "1.0.0",
                  "root": { "path": "rootfs" },
                  "process": {
                    "args": ["sh", "-c", "echo hi"]
                  }
                }
                """.trimIndent()
        val spec = Json.decode(json, Spec::fromJson)!!
        assertEquals("1.0.0", spec.ociVersion)
        assertEquals("rootfs", spec.root!!.path)
        assertEquals(3, spec.process!!.args.size)
        assertEquals("sh", spec.process!!.args[0])
    }

    @Test
    fun unknownFieldsAreIgnored() {
        // The OCI spec mandates that runtimes MUST NOT fail on unknown
        // properties — we rely on Jackson's FAIL_ON_UNKNOWN_PROPERTIES=false.
        val json = """
                {
                  "ociVersion": "1.2.0",
                  "root": { "path": "rootfs" },
                  "process": { "args": ["true"] },
                  "thisFieldDoesNotExist": { "nested": 42 },
                  "unknown": "garbage"
                }
                """.trimIndent()
        val spec = Json.decode(json, Spec::fromJson)!!
        assertEquals("1.2.0", spec.ociVersion)
    }

    @Test
    fun hasNamespaceReturnsTrueForListedTypes() {
        val spec = Spec()
        spec.linux = Spec.Linux()
        val mnt = Spec.Namespace()
        mnt.type = "mount"
        val pid = Spec.Namespace()
        pid.type = "pid"
        spec.linux!!.namespaces = listOf(mnt, pid)

        assertTrue(spec.hasNamespace("mount"))
        assertTrue(spec.hasNamespace("pid"))
        assertFalse(spec.hasNamespace("user"),
            "user is not in the spec so hasNamespace must return false")
        assertFalse(spec.hasNamespace("network"))
    }

    @Test
    fun hasNamespaceWithNullLinuxIsSafe() {
        val spec = Spec()
        spec.linux = null
        assertFalse(spec.hasNamespace("mount"))
    }

    @Test
    fun capabilitiesFieldRoundTrips() {
        val json = """
                {
                  "ociVersion": "1.0.0",
                  "root": { "path": "rootfs" },
                  "process": {
                    "args": ["true"],
                    "capabilities": {
                      "bounding": ["CAP_DAC_OVERRIDE", "CAP_KILL"],
                      "effective": ["CAP_DAC_OVERRIDE"]
                    }
                  }
                }
                """.trimIndent()
        val spec = Json.decode(json, Spec::fromJson)!!
        assertNotNull(spec.process!!.capabilities)
        assertEquals(2, spec.process!!.capabilities!!.bounding!!.size)
        assertTrue(spec.process!!.capabilities!!.bounding!!.contains("CAP_KILL"))
        assertEquals(1, spec.process!!.capabilities!!.effective!!.size)
    }

    @Test
    fun mountUidMappingsParseForIdmapMounts() {
        val json = """
                {
                  "ociVersion": "1.0.0",
                  "root": { "path": "rootfs" },
                  "process": { "args": ["true"] },
                  "mounts": [{
                    "destination": "/idmap",
                    "source": "/tmp",
                    "type": "none",
                    "options": ["bind"],
                    "uidMappings": [{ "containerID": 0, "hostID": 100000, "size": 1 }],
                    "gidMappings": [{ "containerID": 0, "hostID": 100000, "size": 1 }]
                  }]
                }
                """.trimIndent()
        val spec = Json.decode(json, Spec::fromJson)!!
        assertEquals(1, spec.mounts!!.size)
        val m = spec.mounts!![0]
        assertEquals("/idmap", m.destination)
        assertEquals(1, m.uidMappings!!.size)
        assertEquals(100000, m.uidMappings!![0].hostID)
        assertEquals(0, m.uidMappings!![0].containerID)
        assertEquals(1, m.uidMappings!![0].size)
    }
}
