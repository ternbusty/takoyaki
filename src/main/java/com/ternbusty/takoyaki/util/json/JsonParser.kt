package com.ternbusty.takoyaki.util.json

import java.nio.charset.StandardCharsets

/**
 * Minimal recursive-descent JSON parser.
 *
 * Parses input into a tree of:
 * - [MutableMap]<String, Any?> for JSON objects (insertion-ordered)
 * - [MutableList]<Any?> for JSON arrays
 * - [String] for JSON strings
 * - [Long] for integral numbers, [Double] for fractional or out-of-range
 * - [Boolean] for true/false
 * - `null` for JSON null
 *
 * Why hand-rolled: jackson-databind brings in ~3,000 reachable methods,
 * ~2.6 MB of code, and transitively ~4.6 MB of java.xml at native-image
 * build time. takoyaki only ever parses OCI spec / state JSON — small,
 * well-typed schemas. A 300-line parser is plenty.
 *
 * Not goals: streaming, performance for huge files, lenient JSON5,
 * comments, trailing commas. The OCI conformance test corpus is the
 * spec we care about.
 */
class JsonParser private constructor(private val src: String) {
    private var pos: Int = 0

    companion object {
        fun parse(s: String): Any? {
            val p = JsonParser(s)
            val v = p.readValue()
            p.skipWs()
            if (p.pos != p.src.length) {
                throw p.error("trailing data after value")
            }
            return v
        }

        fun parse(bytes: ByteArray): Any? =
            parse(String(bytes, StandardCharsets.UTF_8))
    }

    private fun readValue(): Any? {
        skipWs()
        if (pos >= src.length) throw error("unexpected EOF")
        return when (src[pos]) {
            '{' -> readObject()
            '[' -> readArray()
            '"' -> readString()
            't' -> readKeyword("true", true)
            'f' -> readKeyword("false", false)
            'n' -> readKeyword("null", null)
            else -> readNumber()
        }
    }

    private fun readObject(): MutableMap<String, Any?> {
        pos++ // consume '{'
        val m = LinkedHashMap<String, Any?>()
        skipWs()
        if (peek('}')) { pos++; return m }
        while (true) {
            skipWs()
            if (!peek('"')) throw error("expected string key")
            val k = readString()
            skipWs()
            if (!peek(':')) throw error("expected ':' after key")
            pos++
            m[k] = readValue()
            skipWs()
            if (peek(',')) { pos++; continue }
            if (peek('}')) { pos++; return m }
            throw error("expected ',' or '}' in object")
        }
    }

    private fun readArray(): MutableList<Any?> {
        pos++ // consume '['
        val a = ArrayList<Any?>()
        skipWs()
        if (peek(']')) { pos++; return a }
        while (true) {
            a.add(readValue())
            skipWs()
            if (peek(',')) { pos++; continue }
            if (peek(']')) { pos++; return a }
            throw error("expected ',' or ']' in array")
        }
    }

    private fun readString(): String {
        if (!peek('"')) throw error("expected '\"'")
        pos++
        val sb = StringBuilder()
        while (pos < src.length) {
            val c = src[pos++]
            if (c == '"') return sb.toString()
            if (c == '\\') {
                if (pos >= src.length) throw error("bad escape at EOF")
                val e = src[pos++]
                when (e) {
                    '"', '\\', '/' -> sb.append(e)
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> {
                        if (pos + 4 > src.length) throw error("bad \\u escape")
                        val code = src.substring(pos, pos + 4).toInt(16)
                        sb.append(code.toChar())
                        pos += 4
                    }
                    else -> throw error("bad escape '\\$e'")
                }
            } else {
                sb.append(c)
            }
        }
        throw error("unterminated string")
    }

    private fun readKeyword(kw: String, value: Any?): Any? {
        if (pos + kw.length > src.length || !src.startsWith(kw, pos)) {
            throw error("expected '$kw'")
        }
        pos += kw.length
        return value
    }

    private fun readNumber(): Any {
        val start = pos
        var fractional = false
        if (pos < src.length && src[pos] == '-') pos++
        val digitsStart = pos
        while (pos < src.length) {
            val c = src[pos]
            if (c in '0'..'9') { pos++; continue }
            if (c == '.' || c == 'e' || c == 'E') {
                fractional = true; pos++; continue
            }
            if (fractional && (c == '+' || c == '-')) { pos++; continue }
            break
        }
        // Require at least one digit. Without this, bareword input like
        // "yes" falls into readNumber() (default in readValue switch) and
        // Double.parseDouble("") throws NumberFormatException — which masks
        // the real "unknown token" message.
        if (pos == digitsStart) {
            throw error("expected JSON value, got '${src[start]}'")
        }
        val s = src.substring(start, pos)
        if (fractional) return s.toDouble()
        return try {
            s.toLong()
        } catch (_: NumberFormatException) {
            s.toDouble()
        }
    }

    private fun skipWs() {
        while (pos < src.length) {
            val c = src[pos]
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++
            else break
        }
    }

    private fun peek(c: Char): Boolean =
        pos < src.length && src[pos] == c

    private fun error(msg: String): IllegalStateException =
        IllegalStateException("json parse: $msg at pos $pos")
}
