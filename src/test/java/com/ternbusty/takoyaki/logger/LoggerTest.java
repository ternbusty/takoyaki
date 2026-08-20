package com.ternbusty.takoyaki.logger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;

class LoggerTest {

    private PrintStream originalOut;
    private ByteArrayOutputStream captured;

    @BeforeEach
    void redirectLoggerOutput() throws Exception {
        captured = new ByteArrayOutputStream();
        Field f = Logger.class.getDeclaredField("out");
        f.setAccessible(true);
        originalOut = (PrintStream) f.get(null);
        f.set(null, new PrintStream(captured, true));
        // The production default is OFF. Most tests expect INFO or higher,
        // so set it here for deterministic ordering.
        Logger.setLevel(Logger.Level.INFO);
    }

    @AfterEach
    void restoreLoggerOutput() throws Exception {
        Field f = Logger.class.getDeclaredField("out");
        f.setAccessible(true);
        f.set(null, originalOut);
        // Reset shared state we mutated.
        Logger.setLevel(Logger.Level.INFO);
        Logger.setFormat(Logger.Format.TEXT);
        Logger.setContext("main");
    }

    // ---- escape() -----------------------------------------------------------
    // JSON output runs every log line through escape(). A bug here corrupts the
    // JSON we feed to log aggregators (Loki, journald-json).

    @Test
    void escapePassesThroughPlainAscii() {
        assertEquals("hello world", Logger.escape("hello world"));
    }

    @Test
    void escapeEscapesBackslashAndQuote() {
        assertEquals("a\\\\b\\\"c", Logger.escape("a\\b\"c"));
    }

    @Test
    void escapeMapsNewlineCarriageReturnTab() {
        assertEquals("\\n\\r\\t", Logger.escape("\n\r\t"));
    }

    @Test
    void escapeEmitsUnicodeForOtherControlCharacters() {
        // Below 0x20 anything not specifically handled gets the JSON
        // backslash-u four-hex-digit form. Char 0x01 must escape to literal six chars.
        String input = String.valueOf((char) 0x01);
        assertEquals("\\u0001", Logger.escape(input));
    }

    @Test
    void escapeLeavesNonAsciiAlone() {
        // Multibyte chars are not encoded. UTF-8 output is fine for the
        // consumers we care about.
        assertEquals("漢字", Logger.escape("漢字"));
    }

    // ---- level filter -------------------------------------------------------

    @Test
    void debugIsDroppedAtInfoLevel() {
        // Level is INFO (set by @BeforeEach). debug() must emit NOTHING.
        Logger.debug("not-shown");
        assertEquals("", captured.toString(),
                "DEBUG must be suppressed when level=INFO");
    }

    @Test
    void infoLevelEmitsInfoAndHigher() {
        Logger.info("shown-info");
        Logger.warn("shown-warn");
        Logger.error("shown-err");
        String out = captured.toString();
        assertTrue(out.contains("shown-info"));
        assertTrue(out.contains("shown-warn"));
        assertTrue(out.contains("shown-err"));
    }

    @Test
    void settingLevelToDebugAllowsEverything() {
        Logger.setLevel(Logger.Level.DEBUG);
        Logger.debug("trace");
        assertTrue(captured.toString().contains("trace"));
    }

    @Test
    void settingLevelToErrorSuppressesInfoAndWarn() {
        Logger.setLevel(Logger.Level.ERROR);
        Logger.info("no");
        Logger.warn("no");
        Logger.error("yes");
        String out = captured.toString();
        assertFalse(out.contains("no"));
        assertTrue(out.contains("yes"));
    }

    @Test
    void textFormatContainsLogrusStyleLevelAndMessage() {
        Logger.setFormat(Logger.Format.TEXT);
        Logger.info("hi");
        String out = captured.toString();
        // logrus-compatible format: time="..." level=info msg="hi"
        assertTrue(out.contains("level=info"),
                () -> "missing logrus level tag, got: " + out);
        assertTrue(out.contains("msg=\"hi\""),
                () -> "missing logrus msg field, got: " + out);
        assertTrue(out.contains("time=\""),
                () -> "missing logrus time field, got: " + out);
    }

    @Test
    void jsonFormatProducesParseableJsonShape() {
        Logger.setFormat(Logger.Format.JSON);
        Logger.info("hello\"world");
        String out = captured.toString().trim();
        // Don't pin the timestamp. Check structure and escaped quote.
        assertTrue(out.startsWith("{"));
        assertTrue(out.endsWith("}"));
        assertTrue(out.contains("\"level\":\"info\""), () -> "wrong level field: " + out);
        assertTrue(out.contains("\"msg\":\"hello\\\"world\""),
                () -> "quote not escaped in JSON: " + out);
        assertTrue(out.contains("\"time\":\""), () -> "missing time field: " + out);
    }
}
