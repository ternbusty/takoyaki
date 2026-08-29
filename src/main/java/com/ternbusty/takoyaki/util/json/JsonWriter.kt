package com.ternbusty.takoyaki.util.json

/**
 * Writes a [JsonParser]-shaped tree (Map, List, String, Long, Double,
 * Boolean, null) back as JSON text.
 *
 * Pretty-prints by default with 2-space indent — the OCI conformance
 * suite parses both formats, but pretty output is human-readable and
 * matches what jackson's `writerWithDefaultPrettyPrinter` produced
 * for our state.json files. [toCompact] is available for places
 * we want one-line output (currently unused; OCI doesn't care).
 *
 * Encoding rules: 32-bit and 64-bit integers go through as JSON numbers
 * without decimal points; doubles round-trip via [Double.toString].
 * Strings escape only the characters strict JSON forbids unescaped (control
 * chars + `"` + `\`); we do not pre-escape forward slash.
 */
object JsonWriter {
    private const val INDENT = "  "

    fun toPretty(node: Any?): String {
        val sb = StringBuilder()
        writeValue(sb, node, 0, true)
        return sb.toString()
    }

    fun toCompact(node: Any?): String {
        val sb = StringBuilder()
        writeValue(sb, node, 0, false)
        return sb.toString()
    }

    @Suppress("UNCHECKED_CAST")
    private fun writeValue(sb: StringBuilder, v: Any?, depth: Int, pretty: Boolean) {
        when {
            v == null -> sb.append("null")
            v is Boolean -> sb.append(if (v) "true" else "false")
            v is String -> writeString(sb, v)
            v is Number -> writeNumber(sb, v)
            v is Map<*, *> -> writeObject(sb, v as Map<String, Any?>, depth, pretty)
            v is List<*> -> writeArray(sb, v as List<Any?>, depth, pretty)
            else -> throw IllegalArgumentException("json write: unsupported type ${v.javaClass}")
        }
    }

    private fun writeObject(sb: StringBuilder, m: Map<String, Any?>, depth: Int, pretty: Boolean) {
        if (m.isEmpty()) { sb.append("{ }"); return }
        sb.append('{')
        var first = true
        for ((key, value) in m) {
            if (!first) sb.append(',')
            first = false
            if (pretty) { sb.append('\n'); indent(sb, depth + 1) }
            writeString(sb, key)
            sb.append(if (pretty) " : " else ":")
            writeValue(sb, value, depth + 1, pretty)
        }
        if (pretty) { sb.append('\n'); indent(sb, depth) }
        sb.append('}')
    }

    private fun writeArray(sb: StringBuilder, a: List<Any?>, depth: Int, pretty: Boolean) {
        if (a.isEmpty()) { sb.append("[ ]"); return }
        sb.append('[')
        var first = true
        for (e in a) {
            if (!first) sb.append(',')
            first = false
            if (pretty) { sb.append('\n'); indent(sb, depth + 1) }
            writeValue(sb, e, depth + 1, pretty)
        }
        if (pretty) { sb.append('\n'); indent(sb, depth) }
        sb.append(']')
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> {
                    if (c < ' ') {
                        sb.append("\\u%04x".format(c.code))
                    } else {
                        sb.append(c)
                    }
                }
            }
        }
        sb.append('"')
    }

    private fun writeNumber(sb: StringBuilder, n: Number) {
        when (n) {
            is Long, is Int, is Short, is Byte -> sb.append(n.toLong())
            is Double, is Float -> {
                val d = n.toDouble()
                if (d.isNaN() || d.isInfinite()) {
                    throw IllegalArgumentException("json write: non-finite number $d")
                }
                // Prefer integer form when possible — keeps state.json clean
                // (`pid: 4242` not `pid: 4242.0`).
                if (d == Math.rint(d) && Math.abs(d) < 1e15) {
                    sb.append(d.toLong())
                } else {
                    sb.append(d)
                }
            }
            else -> sb.append(n)
        }
    }

    private fun indent(sb: StringBuilder, depth: Int) {
        repeat(depth) { sb.append(INDENT) }
    }
}
