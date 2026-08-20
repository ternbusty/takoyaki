package com.ternbusty.takoyaki.logger;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public final class Logger {
    public enum Level { DEBUG, INFO, WARN, ERROR, OFF }

    public enum Format { TEXT, JSON }

    private static volatile Level level = Level.OFF;
    private static volatile String context = "main";
    private static volatile PrintStream out = System.err;
    private static volatile Format format = Format.TEXT;
    private static volatile String logFilePath = null;

    private Logger() {}

    public static void setLevel(Level l) { level = l; }
    public static void setContext(String c) { context = c; }
    public static void setFormat(Format f) { format = f; }

    /** Return the configured log file path, or null when writing to stderr. */
    public static String getLogFilePath() { return logFilePath; }

    /** Return the format name ("json" or "text"), or null for the default. */
    public static String getFormatName() {
        return format == Format.JSON ? "json" : null;
    }

    public static void setLogFile(String path) {
        try {
            out = new PrintStream(Files.newOutputStream(Path.of(path),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND));
            logFilePath = path;
        } catch (IOException e) {
            System.err.println("[logger] failed to open log file " + path + ": " + e.getMessage());
        }
    }

    public static boolean isDebugEnabled() { return Level.DEBUG.ordinal() >= level.ordinal(); }

    public static void debug(String msg) { log(Level.DEBUG, msg); }
    public static void info(String msg) { log(Level.INFO, msg); }
    public static void warn(String msg) { log(Level.WARN, msg); }
    public static void error(String msg) { log(Level.ERROR, msg); }

    private static void log(Level l, String msg) {
        if (l.ordinal() < level.ordinal()) return;
        if (format == Format.JSON) {
            String ts = OffsetDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            out.println("{\"level\":\"" + l.name().toLowerCase()
                    + "\",\"msg\":\"" + escape(msg)
                    + "\",\"time\":\"" + ts + "\"}");
        } else {
            // logrus-compatible text format so runc bats tests can match
            // "level=debug" and similar substrings.
            String ts = OffsetDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
            out.println("time=\"" + ts + "\" level=" + l.name().toLowerCase()
                    + " msg=\"" + msg + "\"");
        }
        out.flush();
    }

    /** JSON-escape a log message. Package-visible for unit tests. */
    static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"'  -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }
}
