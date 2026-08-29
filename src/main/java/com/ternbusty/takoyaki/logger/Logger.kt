package com.ternbusty.takoyaki.logger

import java.io.IOException
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

object Logger {
    enum class Level { DEBUG, INFO, WARN, ERROR, OFF }

    enum class Format { TEXT, JSON }

    @Volatile var level: Level = Level.OFF
    @Volatile var context: String = "main"
    @Volatile private var out: PrintStream = System.err
    @Volatile var format: Format = Format.TEXT
    @Volatile var logFilePath: String? = null
        private set

    /** Return the format name ("json" or "text"), or null for the default. */
    val formatName: String?
        get() = if (format == Format.JSON) "json" else null

    fun setLogFile(path: String) {
        try {
            out = PrintStream(Files.newOutputStream(Path.of(path),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND))
            logFilePath = path
        } catch (e: IOException) {
            System.err.println("[logger] failed to open log file $path: ${e.message}")
        }
    }

    val isDebugEnabled: Boolean
        get() = Level.DEBUG.ordinal >= level.ordinal

    fun debug(msg: String): Unit = log(Level.DEBUG, msg)
    fun info(msg: String): Unit = log(Level.INFO, msg)
    fun warn(msg: String): Unit = log(Level.WARN, msg)
    fun error(msg: String): Unit = log(Level.ERROR, msg)

    private fun log(l: Level, msg: String) {
        if (l.ordinal < level.ordinal) return
        if (format == Format.JSON) {
            val ts = OffsetDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            out.println("{\"level\":\"${l.name.lowercase()}\",\"msg\":\"${escape(msg)}\",\"time\":\"$ts\"}")
        } else {
            // logrus-compatible text format so runc bats tests can match
            // "level=debug" and similar substrings.
            val ts = OffsetDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            out.println("time=\"$ts\" level=${l.name.lowercase()} msg=\"$msg\"")
        }
        out.flush()
    }

    /** JSON-escape a log message. Internal for unit tests. */
    internal fun escape(s: String): String {
        val sb = StringBuilder(s.length + 16)
        for (c in s) {
            when (c) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (c < ' ') sb.append("\\u%04x".format(c.code))
                    else sb.append(c)
                }
            }
        }
        return sb.toString()
    }
}
