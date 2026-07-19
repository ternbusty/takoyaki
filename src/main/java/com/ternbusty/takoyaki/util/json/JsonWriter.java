package com.ternbusty.takoyaki.util.json;

import java.util.List;
import java.util.Map;

/**
 * Writes a {@link JsonParser}-shaped tree (Map, List, String, Long, Double,
 * Boolean, null) back as JSON text.
 *
 * <p>Pretty-prints by default with 2-space indent — the OCI conformance
 * suite parses both formats, but pretty output is human-readable and
 * matches what jackson's {@code writerWithDefaultPrettyPrinter} produced
 * for our state.json files. {@link #toCompact} is available for places
 * we want one-line output (currently unused; OCI doesn't care).
 *
 * <p>Encoding rules: 32-bit and 64-bit integers go through as JSON numbers
 * without decimal points; doubles round-trip via {@link Double#toString}.
 * Strings escape only the characters strict JSON forbids unescaped (control
 * chars + {@code "} + {@code \\}); we do not pre-escape forward slash.
 */
public final class JsonWriter {
    private static final String INDENT = "  ";

    private JsonWriter() {}

    public static String toPretty(Object node) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, node, 0, true);
        return sb.toString();
    }

    public static String toCompact(Object node) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, node, 0, false);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object v, int depth, boolean pretty) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof Boolean b) { sb.append(b ? "true" : "false"); return; }
        if (v instanceof String s) { writeString(sb, s); return; }
        if (v instanceof Number n) { writeNumber(sb, n); return; }
        if (v instanceof Map<?, ?> m) { writeObject(sb, (Map<String, Object>) m, depth, pretty); return; }
        if (v instanceof List<?> l) { writeArray(sb, (List<Object>) l, depth, pretty); return; }
        throw new IllegalArgumentException("json write: unsupported type " + v.getClass());
    }

    private static void writeObject(StringBuilder sb, Map<String, Object> m, int depth, boolean pretty) {
        if (m.isEmpty()) { sb.append("{ }"); return; }
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            if (pretty) { sb.append('\n'); indent(sb, depth + 1); }
            writeString(sb, e.getKey());
            sb.append(pretty ? " : " : ":");
            writeValue(sb, e.getValue(), depth + 1, pretty);
        }
        if (pretty) { sb.append('\n'); indent(sb, depth); }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<Object> a, int depth, boolean pretty) {
        if (a.isEmpty()) { sb.append("[ ]"); return; }
        sb.append('[');
        boolean first = true;
        for (Object e : a) {
            if (!first) sb.append(',');
            first = false;
            if (pretty) { sb.append('\n'); indent(sb, depth + 1); }
            writeValue(sb, e, depth + 1, pretty);
        }
        if (pretty) { sb.append('\n'); indent(sb, depth); }
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static void writeNumber(StringBuilder sb, Number n) {
        if (n instanceof Long || n instanceof Integer || n instanceof Short || n instanceof Byte) {
            sb.append(n.longValue());
        } else if (n instanceof Double || n instanceof Float) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("json write: non-finite number " + d);
            }
            // Prefer integer form when possible — keeps state.json clean
            // (`pid: 4242` not `pid: 4242.0`).
            if (d == Math.rint(d) && Math.abs(d) < 1e15) {
                sb.append((long) d);
            } else {
                sb.append(d);
            }
        } else {
            sb.append(n);
        }
    }

    private static void indent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) sb.append(INDENT);
    }
}
