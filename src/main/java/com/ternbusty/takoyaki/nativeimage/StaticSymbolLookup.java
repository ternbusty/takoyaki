package com.ternbusty.takoyaki.nativeimage;

import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CTypeConversion;
import org.graalvm.word.PointerBase;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.util.Optional;

/**
 * {@link SymbolLookup} for fully-static (musl) builds where
 * {@code dlopen}/{@code dlsym} are non-functional.  Delegates to a C
 * lookup table ({@code static_lookup.c}) linked into the binary via
 * {@code --whole-archive}, so every symbol is resolved by the static
 * linker at build time — no dynamic loader involved.
 */
public final class StaticSymbolLookup implements SymbolLookup {

    public static final SymbolLookup INSTANCE = new StaticSymbolLookup();

    private StaticSymbolLookup() {}

    @CFunction("takoyaki_static_lookup")
    private static native PointerBase nativeLookup(CCharPointer name);

    @Override
    public Optional<MemorySegment> find(String name) {
        try (CTypeConversion.CCharPointerHolder pin = CTypeConversion.toCString(name)) {
            PointerBase result = nativeLookup(pin.get());
            if (result.isNull()) {
                return Optional.empty();
            }
            return Optional.of(MemorySegment.ofAddress(result.rawValue()));
        }
    }
}
