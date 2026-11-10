package com.ternbusty.takoyaki.ffigen;

import java.io.IOException;
import java.lang.foreign.AddressLayout;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.UnionLayout;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Build-time generator for the native function bindings takoyaki calls.
 *
 * <p>jextract binds each function through a downcall handle created at run
 * time from the symbol address. In the image that means a symbol lookup per
 * function and, unless the handle is an image-build constant, SubstrateVM's
 * generic {@code invokeExact} path (~2 us per call). A static executable
 * cannot look symbols up at all.
 *
 * <p>This generator reads the compiled jextract output ({@code NativeHRaw},
 * {@code NativeHRaw_1}, ...) by reflection and writes
 * {@code syscall.gen.NativeH extends NativeHRaw}: for every function whose
 * descriptor has only scalar and pointer layouts, a static method with the
 * same signature that hides the inherited one. In the image it calls the
 * function through a {@code @CFunction} declaration, which the linker resolves,
 * so a call compiles to a direct native call and needs no lookup. On the JVM
 * (the generators and the unit tests) it calls the jextract binding instead.
 * A union of pointers passed by value (glibc's transparent sockaddr unions)
 * counts as a pointer: the method keeps taking the union and passes the
 * pointer it holds. Everything else (constants, structs, variadic invokers,
 * struct-by-value functions) is inherited unchanged; calling one of those
 * functions in the image fails with "unresolved symbol", as the image has no
 * symbol lookup.
 *
 * <p>Variadic functions have no fixed descriptor: jextract only offers
 * {@code makeInvoker(layouts...)}. The specialisations takoyaki needs are passed
 * on the command line as {@code name:LAYOUT,...} (the variadic layouts, jextract
 * names such as {@code C_LONG}). For each one this writes a static method taking
 * the fixed and the variadic arguments, e.g.
 * {@code NativeH.syscall(long, long, long, ...)}. {@code @CFunction} does not
 * support the varargs calling convention, so in the image the method calls a
 * fixed-arity C wrapper, {@code takoyaki_<name>} in bootstrap/varargs.c, which
 * must exist for every specialisation.
 *
 * <p>Usage: {@code GenerateFastBindings <output source dir> [name:LAYOUT,...]...}
 */
public final class GenerateFastBindings {
    private static final String PKG = "com.ternbusty.takoyaki.syscall.gen";
    private static final String RAW = PKG + ".NativeHRaw";

    /** Same definition as jextract's C_POINTER. */
    private static final AddressLayout C_POINTER = ValueLayout.ADDRESS.withTargetLayout(
            MemoryLayout.sequenceLayout(Long.MAX_VALUE, ValueLayout.JAVA_BYTE));

    /**
     * Layouts a {@code @CFunction} declaration can take: their carriers map to
     * the C types one to one. boolean and char are left out on purpose.
     */
    private static final Set<MemoryLayout> SUPPORTED = Set.of(
            ValueLayout.JAVA_BYTE, ValueLayout.JAVA_SHORT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_FLOAT, ValueLayout.JAVA_DOUBLE, ValueLayout.ADDRESS, C_POINTER);

    private static final Map<String, MemoryLayout> JEXTRACT_NAMES = Map.of(
            "C_CHAR", ValueLayout.JAVA_BYTE,
            "C_SHORT", ValueLayout.JAVA_SHORT,
            "C_INT", ValueLayout.JAVA_INT,
            "C_LONG", ValueLayout.JAVA_LONG,
            "C_LONG_LONG", ValueLayout.JAVA_LONG,
            "C_DOUBLE", ValueLayout.JAVA_DOUBLE,
            "C_POINTER", C_POINTER);

    /**
     * One generated function: the Java parameter and return types, the C
     * symbol the image calls, and for a variadic specialisation the jextract
     * names of its variadic layouts (null otherwise).
     */
    private record Fn(String name, List<Class<?>> params, Class<?> ret, List<Integer> pointerUnions,
                      FunctionDescriptor desc, String symbol, List<String> variadicLayouts) {}

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
                if (m == null || !isSupported(desc)) {
                    skipped++;
                    continue;
                }
                fns.add(new Fn(holder.getSimpleName(), List.of(m.getParameterTypes()), m.getReturnType(),
                        pointerUnionArgs(desc), desc, holder.getSimpleName(), null));
            }
        }
        for (int i = 1; i < args.length; i++) {
            fns.add(variadic(args[i], variadicHolders));
        }
        writeNativeH(out, fns);
        System.out.printf("GenerateFastBindings: %d functions (%d variadic), %d left to jextract%n",
                fns.size(), args.length - 1, skipped);
    }

    /** A {@code name:LAYOUT,...} variadic specialisation. */
    private static Fn variadic(String spec, Map<String, Class<?>> holders) {
        int colon = spec.indexOf(':');
        String name = colon < 0 ? spec : spec.substring(0, colon);
        Class<?> holder = holders.get(name);
        if (holder == null) throw new IllegalArgumentException("no variadic function " + name + " in the bindings");
        FunctionDescriptor base = descriptorOf(holder, "BASE_DESC");
        if (base == null) throw new IllegalArgumentException("cannot read BASE_DESC of " + name);
        List<String> names = new ArrayList<>();
        List<MemoryLayout> extra = new ArrayList<>();
        if (colon >= 0 && colon < spec.length() - 1) {
            for (String l : spec.substring(colon + 1).split(",")) {
                MemoryLayout layout = JEXTRACT_NAMES.get(l.trim());
                if (layout == null) throw new IllegalArgumentException("unknown layout " + l + " in " + spec);
                names.add(l.trim());
                extra.add(layout);
            }
        }
        FunctionDescriptor desc = base.appendArgumentLayouts(extra.toArray(MemoryLayout[]::new));
        if (!isSupported(desc)) throw new IllegalArgumentException("unsupported layout in " + spec);
        List<Class<?>> params = new ArrayList<>();
        for (MemoryLayout l : desc.argumentLayouts()) params.add(((ValueLayout) l).carrier());
        Class<?> ret = desc.returnLayout().isPresent()
                ? ((ValueLayout) desc.returnLayout().get()).carrier()
                : void.class;
        return new Fn(name, params, ret, List.of(), desc, "takoyaki_" + name, names);
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

    /** Whether every layout of the descriptor can be passed through a {@code @CFunction}. */
    private static boolean isSupported(FunctionDescriptor desc) {
        for (MemoryLayout l : desc.argumentLayouts()) {
            if (!isPointerUnion(l) && !SUPPORTED.contains(l)) return false;
        }
        return desc.returnLayout().map(SUPPORTED::contains).orElse(true);
    }

    /**
     * A union of pointers passed by value: glibc's transparent unions such as
     * {@code __CONST_SOCKADDR_ARG} for bind, connect and accept. The C ABI
     * passes a transparent union as its first member, so the call takes the
     * pointer itself.
     */
    private static boolean isPointerUnion(MemoryLayout l) {
        return l instanceof UnionLayout u && u.byteSize() == ValueLayout.ADDRESS.byteSize()
                && u.memberLayouts().stream().allMatch(m -> m instanceof AddressLayout);
    }

    private static List<Integer> pointerUnionArgs(FunctionDescriptor desc) {
        List<Integer> idx = new ArrayList<>();
        for (int i = 0; i < desc.argumentLayouts().size(); i++) {
            if (isPointerUnion(desc.argumentLayouts().get(i))) idx.add(i);
        }
        return idx;
    }

    private static void writeNativeH(Path out, List<Fn> fns) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("package ").append(PKG).append(";\n\n")
          .append("import java.lang.foreign.MemorySegment;\n")
          .append("import java.lang.foreign.ValueLayout;\n")
          .append("import org.graalvm.nativeimage.ImageInfo;\n")
          .append("import org.graalvm.nativeimage.c.function.CFunction;\n")
          .append("import org.graalvm.word.PointerBase;\n")
          .append("import org.graalvm.word.WordFactory;\n\n")
          .append("/**\n")
          .append(" * jextract bindings that call C through @CFunction in the image and through\n")
          .append(" * the jextract downcall handles on the JVM. Generated by GenerateFastBindings;\n")
          .append(" * do not edit. Functions hide the ones inherited from NativeHRaw; everything\n")
          .append(" * else is inherited unchanged.\n")
          .append(" */\n")
          .append("@SuppressWarnings(\"unused\")\n")
          .append("public class NativeH extends NativeHRaw {\n")
          .append("    NativeH() {}\n");
        for (Fn fn : fns) {
            String name = fn.name();
            Class<?> ret = fn.ret();
            StringBuilder params = new StringBuilder();
            StringBuilder nativeParams = new StringBuilder();
            StringBuilder argNames = new StringBuilder();
            StringBuilder callArgs = new StringBuilder();
            Class<?>[] pt = fn.params().toArray(Class<?>[]::new);
            for (int i = 0; i < pt.length; i++) {
                if (i > 0) {
                    params.append(", ");
                    nativeParams.append(", ");
                    argNames.append(", ");
                    callArgs.append(", ");
                }
                params.append(typeName(pt[i])).append(" x").append(i);
                nativeParams.append(nativeTypeName(pt[i])).append(" x").append(i);
                argNames.append("x").append(i);
                if (fn.pointerUnions().contains(i)) {
                    // A pointer union arrives as a segment holding the pointer.
                    callArgs.append("WordFactory.pointer(x").append(i).append(".get(ValueLayout.ADDRESS, 0).address())");
                } else if (pt[i] == MemorySegment.class) {
                    callArgs.append("WordFactory.pointer(x").append(i).append(".address())");
                } else {
                    callArgs.append("x").append(i);
                }
            }
            String call = name + "$c(" + callArgs + ")";
            String jvmCall = fn.variadicLayouts() == null
                    ? "NativeHRaw." + name + "(" + argNames + ")"
                    : "NativeHRaw." + name + ".makeInvoker("
                            + String.join(", ", fn.variadicLayouts().stream().map(l -> "NativeHRaw." + l).toList())
                            + ").apply(" + argNames + ")";
            String returnKw = ret == void.class ? "" : "return ";
            sb.append("\n    @CFunction(\"").append(fn.symbol()).append("\")\n")
              .append("    private static native ").append(nativeTypeName(ret)).append(' ').append(name)
              .append("$c(").append(nativeParams).append(");\n\n")
              .append("    public static ").append(typeName(ret)).append(' ').append(name)
              .append('(').append(params).append(") {\n")
              .append("        if (!ImageInfo.inImageCode()) {\n")
              .append("            ").append(returnKw).append(jvmCall).append(";\n");
            if (ret == void.class) sb.append("            return;\n");
            sb.append("        }\n")
              .append("        if (TRACE_DOWNCALLS) {\n")
              .append("            traceDowncall(\"").append(name).append('"')
              .append(pt.length > 0 ? ", " + argNames : "").append(");\n")
              .append("        }\n");
            if (ret == MemorySegment.class) {
                sb.append("        return ").append(wrapPointer(fn.desc(), call)).append(";\n");
            } else {
                sb.append("        ").append(returnKw).append(call).append(";\n");
            }
            sb.append("    }\n");
        }
        sb.append("}\n");
        write(out, PKG, "NativeH", sb);
    }

    /** The returned pointer as the segment the jextract binding returns: sized by the target layout, if any. */
    private static String wrapPointer(FunctionDescriptor desc, String call) {
        String seg = "MemorySegment.ofAddress(" + call + ".rawValue())";
        if (desc.returnLayout().orElseThrow() instanceof AddressLayout a && a.targetLayout().isPresent()) {
            return seg + ".reinterpret(" + a.targetLayout().get().byteSize() + "L)";
        }
        return seg;
    }

    private static String nativeTypeName(Class<?> c) {
        return c == MemorySegment.class ? "PointerBase" : c.getName();
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
