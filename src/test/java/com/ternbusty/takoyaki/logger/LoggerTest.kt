package com.ternbusty.takoyaki.logger

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import org.junit.jupiter.api.Assertions.*

class LoggerTest {

    private lateinit var originalOut: PrintStream
    private lateinit var captured: ByteArrayOutputStream

    @BeforeEach
    fun redirectLoggerOutput() {
        captured = ByteArrayOutputStream()
        val f = Logger::class.java.getDeclaredField("out")
        f.isAccessible = true
        originalOut = f.get(Logger) as PrintStream
        f.set(Logger, PrintStream(captured, true))
        // The production default is OFF. Most tests expect INFO or higher,
        // so set it here for deterministic ordering.
        Logger.level = Logger.Level.INFO
    }

    @AfterEach
    fun restoreLoggerOutput() {
        val f = Logger::class.java.getDeclaredField("out")
        f.isAccessible = true
        f.set(Logger, originalOut)
        // Reset shared state we mutated.
        Logger.level = Logger.Level.INFO
        Logger.format = Logger.Format.TEXT
        Logger.context = "main"
    }

    // ---- escape() -----------------------------------------------------------
    // JSON output runs every log line through escape(). A bug here corrupts the
    // JSON we feed to log aggregators (Loki, journald-json).

    @Test
    fun escapePassesThroughPlainAscii() {
        assertEquals("hello world", Logger.escape("hello world"))
    }

    @Test
    fun escapeEscapesBackslashAndQuote() {
        assertEquals("a\\\\b\\\"c", Logger.escape("a\\b\"c"))
    }

    @Test
    fun escapeMapsNewlineCarriageReturnTab() {
        assertEquals("\\n\\r\\t", Logger.escape("\n\r\t"))
    }

    @Test
    fun escapeEmitsUnicodeForOtherControlCharacters() {
        // Below 0x20 anything not specifically handled gets the JSON
        // backslash-u four-hex-digit form. Char 0x01 must escape to literal six chars.
        val input = 0x01.toChar().toString()
        assertEquals("\\u0001", Logger.escape(input))
    }

    @Test
    fun escapeLeavesNonAsciiAlone() {
        // Multibyte chars are not encoded. UTF-8 output is fine for the
        // consumers we care about.
        assertEquals("漢字", Logger.escape("漢字"))
    }

    // ---- level filter -------------------------------------------------------

    @Test
    fun debugIsDroppedAtInfoLevel() {
        // Level is INFO (set by @BeforeEach). debug() must emit NOTHING.
        Logger.debug("not-shown")
        assertEquals("", captured.toString(),
            "DEBUG must be suppressed when level=INFO")
    }

    @Test
    fun infoLevelEmitsInfoAndHigher() {
        Logger.info("shown-info")
        Logger.warn("shown-warn")
        Logger.error("shown-err")
        val out = captured.toString()
        assertTrue(out.contains("shown-info"))
        assertTrue(out.contains("shown-warn"))
        assertTrue(out.contains("shown-err"))
    }

    @Test
    fun settingLevelToDebugAllowsEverything() {
        Logger.level = Logger.Level.DEBUG
        Logger.debug("trace")
        assertTrue(captured.toString().contains("trace"))
    }

    @Test
    fun settingLevelToErrorSuppressesInfoAndWarn() {
        Logger.level = Logger.Level.ERROR
        Logger.info("no")
        Logger.warn("no")
        Logger.error("yes")
        val out = captured.toString()
        assertFalse(out.contains("no"))
        assertTrue(out.contains("yes"))
    }

    @Test
    fun textFormatContainsLogrusStyleLevelAndMessage() {
        Logger.format = Logger.Format.TEXT
        Logger.info("hi")
        val out = captured.toString()
        // logrus-compatible format: time="..." level=info msg="hi"
        assertTrue(out.contains("level=info")) { "missing logrus level tag, got: $out" }
        assertTrue(out.contains("msg=\"hi\"")) { "missing logrus msg field, got: $out" }
        assertTrue(out.contains("time=\"")) { "missing logrus time field, got: $out" }
    }

    @Test
    fun jsonFormatProducesParseableJsonShape() {
        Logger.format = Logger.Format.JSON
        Logger.info("hello\"world")
        val out = captured.toString().trim()
        // Don't pin the timestamp. Check structure and escaped quote.
        assertTrue(out.startsWith("{"))
        assertTrue(out.endsWith("}"))
        assertTrue(out.contains("\"level\":\"info\"")) { "wrong level field: $out" }
        assertTrue(out.contains("\"msg\":\"hello\\\"world\"")) { "quote not escaped in JSON: $out" }
        assertTrue(out.contains("\"time\":\"")) { "missing time field: $out" }
    }
}
