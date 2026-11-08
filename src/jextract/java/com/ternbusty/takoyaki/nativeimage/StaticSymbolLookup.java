package com.ternbusty.takoyaki.nativeimage;

import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CTypeConversion;
import org.graalvm.word.PointerBase;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.util.Optional;

/**
 * SymbolLookup for the fully static (musl) build, where dlopen and dlsym do
 * not work. It asks the name/address table that GenerateStaticSymbols writes
 * and the linker fills in; the table is reached through a link-time
 * {@code @CFunction} call. The static build makes it jextract's
 * {@code SYMBOL_LOOKUP}, which is why it lives in the jextract source set;
 * the glibc build does not use it.
 */
public final class StaticSymbolLookup implements SymbolLookup {

    public static final SymbolLookup INSTANCE = new StaticSymbolLookup();

    private StaticSymbolLookup() {}

    @CFunction("takoyaki_static_lookup")
    private static native PointerBase lookup(CCharPointer name);

    @Override
    public Optional<MemorySegment> find(String name) {
        try (CTypeConversion.CCharPointerHolder cName = CTypeConversion.toCString(name)) {
            PointerBase addr = lookup(cName.get());
            return addr.isNull() ? Optional.empty() : Optional.of(MemorySegment.ofAddress(addr.rawValue()));
        }
    }
}
