package com.ternbusty.takoyaki.util

import com.ternbusty.takoyaki.util.json.JsonParser
import com.ternbusty.takoyaki.util.json.JsonWriter
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

/**
 * Thin facade over [JsonParser] and [JsonWriter] matched to
 * the callsites in takoyaki.
 *
 * The shape that flows through here is always a JSON tree —
 * `Map<String, Object> / List<Object> / String / Long / Double /
 * Boolean / null`. Bean-shaped types (Spec, State, KontainerConfig, ...)
 * convert to/from the tree via their static `fromJson(Object)` and
 * instance `toJson()` methods. [readFile] takes the
 * `fromJson` mapper as a function, replacing jackson's
 * `readValue(in, Class)` reflection.
 */
object Json {

    @Throws(IOException::class)
    fun <T> readFile(path: Path, fromJson: (Any?) -> T): T =
        fromJson(JsonParser.parse(Files.readAllBytes(path)))

    @Throws(IOException::class)
    fun writeFile(path: Path, jsonTree: Any?) {
        Files.writeString(path, JsonWriter.toPretty(jsonTree))
    }

    fun encode(jsonTree: Any?): String = JsonWriter.toPretty(jsonTree)

    /** Compact (single-line, no whitespace) JSON encoding. */
    fun encodeCompact(jsonTree: Any?): String = JsonWriter.toCompact(jsonTree)

    fun <T> decode(s: String, fromJson: (Any?) -> T): T =
        fromJson(JsonParser.parse(s))
}
