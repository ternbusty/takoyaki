package com.ternbusty.takoyaki.util.json

import org.junit.jupiter.api.Test
import java.util.LinkedHashMap
import org.junit.jupiter.api.Assertions.*

/**
 * Parser <-> writer roundtrip + spot-checks. We don't aim to be RFC-8259
 * exhaustive; the OCI conformance suite (driven via contestTest) is the
 * functional regression net. These tests catch obvious bugs and pin down
 * the few format choices that downstream tooling depends on.
 */
class JsonRoundtripTest {

    @Test
    fun primitivesRoundtripCorrectTypes() {
        assertEquals("hello", JsonParser.parse("\"hello\""))
        assertEquals(42L, JsonParser.parse("42"))
        assertEquals(-1L, JsonParser.parse("-1"))
        assertEquals(3.14, JsonParser.parse("3.14") as Double, 1e-9)
        assertEquals(true, JsonParser.parse("true"))
        assertEquals(false, JsonParser.parse("false"))
        assertNull(JsonParser.parse("null"))
    }

    @Test
    fun emptyContainers() {
        assertEquals(emptyMap<String, Any>(), JsonParser.parse("{}"))
        assertEquals(emptyList<Any>(), JsonParser.parse("[]"))
    }

    @Test
    fun objectPreservesKeyOrder() {
        val m = cast(JsonParser.parse("{\"z\":1,\"a\":2,\"m\":3}"))
        assertEquals(listOf("z", "a", "m"), m.keys.toList(),
            "downstream tools (runc-compat output) expect insertion order")
    }

    @Test
    fun nestedStructure() {
        val json = "{\"a\":[1,2,{\"b\":\"c\"}]}"
        val m = cast(JsonParser.parse(json))
        val a = m["a"] as List<*>
        assertEquals(3, a.size)
        assertEquals(1L, a[0])
        val inner = a[2] as Map<*, *>
        assertEquals("c", inner["b"])
    }

    @Test
    fun stringEscapes() {
        assertEquals("a\"b", JsonParser.parse("\"a\\\"b\""))
        assertEquals("a\\b", JsonParser.parse("\"a\\\\b\""))
        assertEquals("line1\nline2", JsonParser.parse("\"line1\\nline2\""))
        // backslash-u escape
        assertEquals("\u00e9", JsonParser.parse("\"\\u00e9\""))
    }

    @Test
    fun writerEmitsValidJson() {
        val m = LinkedHashMap<String, Any?>()
        m["name"] = "ctr-a"
        m["pid"] = 4242L
        m["running"] = true
        m["missing"] = null
        val s = JsonWriter.toPretty(m)
        // re-parse to verify it's valid
        val back = cast(JsonParser.parse(s))
        assertEquals("ctr-a", back["name"])
        assertEquals(4242L, back["pid"])
        assertEquals(true, back["running"])
        assertTrue(back.containsKey("missing"))
        assertNull(back["missing"])
    }

    @Test
    fun writerKeepsIntegersAsIntegers() {
        // pid: 4242 should NOT come out as 4242.0 — downstream tooling
        // (containerd, jq) parses it back as float otherwise.
        assertEquals("4242", JsonWriter.toCompact(4242L))
        assertEquals("4242", JsonWriter.toCompact(4242))
        assertEquals("0", JsonWriter.toCompact(0L))
        assertEquals("-1", JsonWriter.toCompact(-1L))
    }

    @Test
    fun writerEscapesControlChars() {
        assertEquals("\"a\\nb\"", JsonWriter.toCompact("a\nb"))
        assertEquals("\"a\\\"b\"", JsonWriter.toCompact("a\"b"))
        assertEquals("\"a\\\\b\"", JsonWriter.toCompact("a\\b"))
    }

    @Test
    fun deepRoundtripPreservesAll() {
        val original = """
                {
                  "ociVersion" : "1.0.0",
                  "root" : { "path" : "rootfs", "readonly" : false },
                  "process" : {
                    "args" : ["/bin/sh", "-c", "echo hi"],
                    "cwd" : "/",
                    "user" : { "uid" : 0, "gid" : 0 }
                  },
                  "mounts" : [
                    { "destination" : "/proc", "type" : "proc", "source" : "proc" }
                  ]
                }""".trimIndent()
        val tree = JsonParser.parse(original)
        val reEmitted = JsonWriter.toPretty(tree)
        val reTree = JsonParser.parse(reEmitted)
        // Structural equality — we don't check string match because formatting
        // can legitimately differ (spaces, trailing newline).
        assertEquals(tree, reTree)
    }

    @Test
    fun parserRejectsTrailingGarbage() {
        assertThrows(IllegalStateException::class.java) { JsonParser.parse("42 garbage") }
    }

    @Test
    fun parserRejectsUnterminatedString() {
        assertThrows(IllegalStateException::class.java) { JsonParser.parse("\"oops") }
    }

    @Test
    fun parserRejectsUnknownKeyword() {
        assertThrows(IllegalStateException::class.java) { JsonParser.parse("yes") }
    }

    @Suppress("UNCHECKED_CAST")
    private fun cast(o: Any?): Map<String, Any?> = o as Map<String, Any?>
}
