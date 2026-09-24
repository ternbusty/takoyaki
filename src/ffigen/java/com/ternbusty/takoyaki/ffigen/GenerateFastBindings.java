package com.ternbusty.takoyaki.ffigen;

import java.io.IOException;
import java.lang.foreign.AddressLayout;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Build-time generator for constant downcall handles.
 *
 * <p>jextract binds each function through a {@code static final MethodHandle}
 * created from the symbol address. The bindings must be initialized at run
 * time (native-image forbids symbol lookup at build time), so those handles
 * are not image-build constants and every call takes SubstrateVM's generic
 * {@code invokeExact} path (~2 us per call).
 *
 * <p>This generator reads the compiled jextract output ({@code NativeHRaw},
 * {@code NativeHRaw_1}, ...) by reflection and writes:
 * <ul>
 *   <li>{@code ffi.Downcalls}: one address-less downcall handle per distinct
 *       function descriptor. It is initialized at build time, so the handles
 *       are constants and calls compile to direct native calls.</li>
 *   <li>{@code syscall.gen.NativeH extends NativeHRaw}: for every function
 *       whose descriptor has only scalar and pointer layouts, a static method
 *       with the same signature that hides the inherited one and invokes the
 *       constant handle with the symbol address, which is still looked up
 *       lazily at run time. Everything else (constants, structs, variadic
 *       invokers, struct-by-value functions) is inherited unchanged.</li>
 * </ul>
 *
 * <p>Variadic functions have no fixed descriptor: jextract only offers
 * {@code makeInvoker(layouts...)}, which builds a handle at run time and calls
 * it through an {@code Object[]} spreader. The specialisations takoyaki needs
 * are passed on the command line as {@code name:LAYOUT,...} (the variadic
 * layouts, jextract names such as {@code C_LONG}). For each one this writes a
 * {@code firstVariadicArg} handle and a static method taking the fixed and the
 * variadic arguments, e.g. {@code NativeH.syscall(long, long, long, ...)}.
 *
 * <p>Compiling constant downcall handles needs native-image from GraalVM 25.3
 * (innovation release) or later; 25.0.x fails with "unexpected input could
 * not be handled: linkToNative".
 *
 * <p>Usage: {@code GenerateFastBindings <output source dir> [name:LAYOUT,...]...}
 */
public final class GenerateFastBindings {
    private static final String PKG = "com.ternbusty.takoyaki.syscall.gen";
    private static final String RAW = PKG + ".NativeHRaw";
    private static final String DOWNCALLS_PKG = "com.ternbusty.takoyaki.ffi";

    /** Same definition as jextract's C_POINTER. */
    private static final AddressLayout C_POINTER = ValueLayout.ADDRESS.withTargetLayout(
            MemoryLayout.sequenceLayout(Long.MAX_VALUE, ValueLayout.JAVA_BYTE));

    private static final Map<MemoryLayout, String> LAYOUTS = new LinkedHashMap<>();
    static {
        LAYOUTS.put(ValueLayout.JAVA_BOOLEAN, "ValueLayout.JAVA_BOOLEAN");
        LAYOUTS.put(ValueLayout.JAVA_BYTE, "ValueLayout.JAVA_BYTE");
        LAYOUTS.put(ValueLayout.JAVA_SHORT, "ValueLayout.JAVA_SHORT");
        LAYOUTS.put(ValueLayout.JAVA_CHAR, "ValueLayout.JAVA_CHAR");
        LAYOUTS.put(ValueLayout.JAVA_INT, "ValueLayout.JAVA_INT");
        LAYOUTS.put(ValueLayout.JAVA_LONG, "ValueLayout.JAVA_LONG");
        LAYOUTS.put(ValueLayout.JAVA_FLOAT, "ValueLayout.JAVA_FLOAT");
        LAYOUTS.put(ValueLayout.JAVA_DOUBLE, "ValueLayout.JAVA_DOUBLE");
        LAYOUTS.put(ValueLayout.ADDRESS, "ValueLayout.ADDRESS");
        LAYOUTS.put(C_POINTER, "C_POINTER");
    }

    private static final Map<String, MemoryLayout> JEXTRACT_NAMES = Map.of(
            "C_BOOL", ValueLayout.JAVA_BOOLEAN,
            "C_CHAR", ValueLayout.JAVA_BYTE,
            "C_SHORT", ValueLayout.JAVA_SHORT,
            "C_INT", ValueLayout.JAVA_INT,
            "C_LONG", ValueLayout.JAVA_LONG,
            "C_LONG_LONG", ValueLayout.JAVA_LONG,
            "C_FLOAT", ValueLayout.JAVA_FLOAT,
            "C_DOUBLE", ValueLayout.JAVA_DOUBLE,
            "C_POINTER", C_POINTER);

    /**
     * One generated function: the Java parameter and return types, and the
     * arguments of {@code Linker.downcallHandle} that the constant handle is built from.
     */
    private record Fn(String name, List<Class<?>> params, Class<?> ret, String handleArgs) {}

    public static void main(String[] args) throws Exception {
        Path out = Path.of(args[0]);
        List<Fn> fns = new ArrayList<>();
        Map<String, Class<?>> variadicHolders = new TreeMap<>();
        int skipped = 0;
        for (int i = 0; ; i++) {
            Class<?> header;
            try {
                header = Class.forName(i == 0 ? RAW : RAW + "_" + i, false,
                        GenerateFastBindings.class.getClassLoader());
            } catch (ClassNotFoundException e) {
                break;
            }
            for (Class<?> holder : header.getDeclaredClasses()) {
                if (Modifier.isPublic(holder.getModifiers())) {
                    // jextract makes only the variadic invokers public.
                    variadicHolders.put(holder.getSimpleName(), holder);
                    continue;
                }
                FunctionDescriptor desc = descriptorOf(holder, "DESC");
                if (desc == null) continue;
                Method m = findMethod(header, holder.getSimpleName(), desc);
                String expr = m == null ? null : descriptorExpr(desc);
                if (expr == null) {
                    skipped++;
                    continue;
                }
                fns.add(new Fn(holder.getSimpleName(), List.of(m.getParameterTypes()), m.getReturnType(), expr));
            }
        }
        for (int i = 1; i < args.length; i++) {
            fns.add(variadic(args[i], variadicHolders));
        }
        // TreeMap keeps the generated files stable across builds.
        Map<String, Integer> handles = new TreeMap<>();
        for (Fn fn : fns) handles.putIfAbsent(fn.handleArgs(), 0);
        int idx = 0;
        for (var e : handles.entrySet()) e.setValue(idx++);

        writeDowncalls(out, handles);
        writeNativeH(out, fns, handles);
        System.out.printf("GenerateFastBindings: %d functions (%d variadic), %d handles, %d left on the generic path%n",
                fns.size(), args.length - 1, handles.size(), skipped);
    }

    /** A {@code name:LAYOUT,...} variadic specialisation. */
    private static Fn variadic(String spec, Map<String, Class<?>> holders) {
        int colon = spec.indexOf(':');
        String name = colon < 0 ? spec : spec.substring(0, colon);
        Class<?> holder = holders.get(name);
        if (holder == null) throw new IllegalArgumentException("no variadic function " + name + " in the bindings");
        FunctionDescriptor base = descriptorOf(holder, "BASE_DESC");
        if (base == null) throw new IllegalArgumentException("cannot read BASE_DESC of " + name);
        List<MemoryLayout> extra = new ArrayList<>();
        if (colon >= 0 && colon < spec.length() - 1) {
            for (String l : spec.substring(colon + 1).split(",")) {
                MemoryLayout layout = JEXTRACT_NAMES.get(l.trim());
                if (layout == null) throw new IllegalArgumentException("unknown layout " + l + " in " + spec);
                extra.add(layout);
            }
        }
        FunctionDescriptor desc = base.appendArgumentLayouts(extra.toArray(MemoryLayout[]::new));
        String expr = descriptorExpr(desc);
        if (expr == null) throw new IllegalArgumentException("unsupported layout in " + spec);
        List<Class<?>> params = new ArrayList<>();
        for (MemoryLayout l : desc.argumentLayouts()) params.add(((ValueLayout) l).carrier());
        Class<?> ret = desc.returnLayout().isPresent()
                ? ((ValueLayout) desc.returnLayout().get()).carrier()
                : void.class;
        return new Fn(name, params, ret,
                expr + ", Linker.Option.firstVariadicArg(" + base.argumentLayouts().size() + ")");
    }

    /** A FunctionDescriptor field of a jextract holder, or null if it is absent or unreadable. */
    private static FunctionDescriptor descriptorOf(Class<?> holder, String field) {
        try {
            Field f = holder.getDeclaredField(field);
            if (!Modifier.isStatic(f.getModifiers()) || f.getType() != FunctionDescriptor.class) return null;
            f.setAccessible(true);
            // Initializes the holder, which also looks the symbol up; a symbol
            // missing on the build machine leaves that function as it is.
            return (FunctionDescriptor) f.get(null);
        } catch (ReflectiveOperationException | LinkageError e) {
            return null;
        }
    }

    private static Method findMethod(Class<?> header, String name, FunctionDescriptor desc) {
        for (Method m : header.getDeclaredMethods()) {
            if (!m.getName().equals(name) || !Modifier.isStatic(m.getModifiers())
                    || !Modifier.isPublic(m.getModifiers())) {
                continue;
            }
            if (m.getParameterCount() != desc.argumentLayouts().size()) continue;
            return m;
        }
        return null;
    }

    /** Java source for the descriptor, or null if it has a struct or other unsupported layout. */
    private static String descriptorExpr(FunctionDescriptor desc) {
        List<String> parts = new ArrayList<>();
        for (MemoryLayout l : desc.argumentLayouts()) {
            String s = LAYOUTS.get(l);
            if (s == null) return null;
            parts.add(s);
        }
        String args = String.join(", ", parts);
        if (desc.returnLayout().isEmpty()) return "FunctionDescriptor.ofVoid(" + args + ")";
        String ret = LAYOUTS.get(desc.returnLayout().get());
        if (ret == null) return null;
        return "FunctionDescriptor.of(" + ret + (args.isEmpty() ? "" : ", " + args) + ")";
    }

    private static void writeDowncalls(Path out, Map<String, Integer> handles) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("package ").append(DOWNCALLS_PKG).append(";\n\n")
          .append("import java.lang.foreign.AddressLayout;\n")
          .append("import java.lang.foreign.FunctionDescriptor;\n")
          .append("import java.lang.foreign.Linker;\n")
          .append("import java.lang.foreign.MemoryLayout;\n")
          .append("import java.lang.foreign.ValueLayout;\n")
          .append("import java.lang.invoke.MethodHandle;\n\n")
          .append("/**\n")
          .append(" * Address-less downcall handles, one per function descriptor. Generated\n")
          .append(" * by GenerateFastBindings; do not edit. Initialized at image build time so\n")
          .append(" * that the handles are constants and calls compile to direct native calls.\n")
          .append(" */\n")
          .append("public final class Downcalls {\n")
          .append("    private Downcalls() {}\n\n")
          .append("    private static final Linker LINKER = Linker.nativeLinker();\n")
          .append("    private static final AddressLayout C_POINTER = ValueLayout.ADDRESS.withTargetLayout(\n")
          .append("            MemoryLayout.sequenceLayout(Long.MAX_VALUE, ValueLayout.JAVA_BYTE));\n\n");
        for (var e : handles.entrySet()) {
            sb.append("    public static final MethodHandle H").append(e.getValue())
              .append(" = LINKER.downcallHandle(").append(e.getKey()).append(");\n");
        }
        sb.append("}\n");
        write(out, DOWNCALLS_PKG, "Downcalls", sb);
    }

    private static void writeNativeH(Path out, List<Fn> fns, Map<String, Integer> handles) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("package ").append(PKG).append(";\n\n")
          .append("import ").append(DOWNCALLS_PKG).append(".Downcalls;\n")
          .append("import java.lang.foreign.MemorySegment;\n\n")
          .append("/**\n")
          .append(" * jextract bindings with constant downcall handles. Generated by\n")
          .append(" * GenerateFastBindings; do not edit. Functions hide the ones inherited from\n")
          .append(" * NativeHRaw; everything else is inherited unchanged.\n")
          .append(" */\n")
          .append("@SuppressWarnings(\"unused\")\n")
          .append("public class NativeH extends NativeHRaw {\n")
          .append("    NativeH() {}\n");
        for (Fn fn : fns) {
            String name = fn.name();
            Class<?> ret = fn.ret();
            StringBuilder params = new StringBuilder();
            StringBuilder argNames = new StringBuilder();
            Class<?>[] pt = fn.params().toArray(Class<?>[]::new);
            for (int i = 0; i < pt.length; i++) {
                if (i > 0) {
                    params.append(", ");
                    argNames.append(", ");
                }
                params.append(typeName(pt[i])).append(" x").append(i);
                argNames.append("x").append(i);
            }
            String call = "Downcalls.H" + handles.get(fn.handleArgs()) + ".invokeExact(a$" + name + ".ADDR"
                    + (pt.length > 0 ? ", " + argNames : "") + ")";
            sb.append("\n    private static final class a$").append(name).append(" {\n")
              .append("        static final MemorySegment ADDR = findOrThrow(\"").append(name).append("\");\n")
              .append("    }\n\n")
              .append("    public static ").append(typeName(ret)).append(' ').append(name)
              .append('(').append(params).append(") {\n")
              .append("        try {\n")
              .append("            if (TRACE_DOWNCALLS) {\n")
              .append("                traceDowncall(\"").append(name).append('"')
              .append(pt.length > 0 ? ", " + argNames : "").append(");\n")
              .append("            }\n");
            if (ret == void.class) {
                sb.append("            ").append(call).append(";\n");
            } else {
                sb.append("            return (").append(typeName(ret)).append(") ").append(call).append(";\n");
            }
            sb.append("        } catch (Throwable ex$) {\n")
              .append("            throw new AssertionError(\"should not reach here\", ex$);\n")
              .append("        }\n")
              .append("    }\n");
        }
        sb.append("}\n");
        write(out, PKG, "NativeH", sb);
    }

    private static String typeName(Class<?> c) {
        return c == MemorySegment.class ? "MemorySegment" : c.getName();
    }

    private static void write(Path out, String pkg, String cls, CharSequence src) throws IOException {
        Path dir = out.resolve(pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(cls + ".java"), src);
    }
}
