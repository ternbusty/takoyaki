package com.ternbusty.takoyaki.util;

import com.ternbusty.takoyaki.util.json.JsonParser;
import com.ternbusty.takoyaki.util.json.JsonWriter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * Thin facade over {@link JsonParser} and {@link JsonWriter} matched to
 * the callsites in takoyaki.
 *
 * <p>The shape that flows through here is always a JSON tree —
 * {@code Map<String,Object> / List<Object> / String / Long / Double /
 * Boolean / null}. Bean-shaped types (Spec, State, KontainerConfig, ...)
 * convert to/from the tree via their static {@code fromJson(Object)} and
 * instance {@code toJson()} methods. {@link #readFile} takes the
 * {@code fromJson} mapper as a {@link Function}, replacing jackson's
 * {@code readValue(in, Class)} reflection.
 */
public final class Json {
    private Json() {}

    public static <T> T readFile(Path path, Function<Object, T> fromJson) throws IOException {
        return fromJson.apply(JsonParser.parse(Files.readAllBytes(path)));
    }

    public static void writeFile(Path path, Object jsonTree) throws IOException {
        Files.writeString(path, JsonWriter.toPretty(jsonTree));
    }

    public static String encode(Object jsonTree) {
        return JsonWriter.toPretty(jsonTree);
    }

    /** Compact (single-line, no whitespace) JSON encoding. */
    public static String encodeCompact(Object jsonTree) {
        return JsonWriter.toCompact(jsonTree);
    }

    public static <T> T decode(String s, Function<Object, T> fromJson) {
        return fromJson.apply(JsonParser.parse(s));
    }
}
