package com.ternbusty.takoyaki.syscall;

import java.lang.foreign.MemorySegment;

/**
 * The checks a downcall handle makes on a segment argument, for the
 * {@code @CFunction} calls in the generated NativeH: they pass
 * {@link #address} rather than the bare address, so passing a heap segment, a
 * segment of a closed arena or one confined to another thread throws as it
 * does with FFM instead of handing C a bad pointer.
 */
public final class NativeArgs {
    private NativeArgs() {}

    public static long address(MemorySegment segment) {
        if (!segment.isNative()) {
            throw new IllegalArgumentException("Heap segment not allowed: " + segment);
        }
        if (!segment.scope().isAlive()) {
            throw new IllegalStateException("Already closed");
        }
        if (!segment.isAccessibleBy(Thread.currentThread())) {
            throw new WrongThreadException("Attempted access outside owning thread");
        }
        return segment.address();
    }
}
