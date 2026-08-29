package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.syscall.gen.NativeH;

import java.lang.foreign.MemoryLayout;

/**
 * Bridge for Kotlin: the Kotlin compiler (2.1.x) cannot access the sealed
 * subtypes {@code ValueLayout.OfLong} / {@code OfInt} / {@code AddressLayout}
 * from JDK 22+. This tiny Java class re-exports the jextract layout constants
 * widened to {@link MemoryLayout} so Kotlin callers can pass them to
 * {@code makeInvoker} without hitting "Cannot access class 'OfLong'".
 *
 * Remove this once the Kotlin compiler supports JDK 22+ sealed ValueLayout
 * subtypes natively.
 */
public final class Layouts {
    private Layouts() {}

    public static final MemoryLayout C_INT = NativeH.C_INT;
    public static final MemoryLayout C_LONG = NativeH.C_LONG;
    public static final MemoryLayout C_POINTER = NativeH.C_POINTER;
}
