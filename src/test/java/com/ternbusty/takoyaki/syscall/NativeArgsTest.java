package com.ternbusty.takoyaki.syscall;

import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NativeArgsTest {

    @Test
    void nativeSegmentGivesItsAddress() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = arena.allocate(16);
            assertEquals(s.address(), NativeArgs.address(s));
        }
    }

    @Test
    void nullSegmentGivesZero() {
        assertEquals(0L, NativeArgs.address(MemorySegment.NULL));
    }

    @Test
    void heapSegmentIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> NativeArgs.address(MemorySegment.ofArray(new byte[16])));
    }

    @Test
    void segmentOfClosedArenaIsRejected() {
        MemorySegment s;
        try (Arena arena = Arena.ofConfined()) {
            s = arena.allocate(16);
        }
        assertThrows(IllegalStateException.class, () -> NativeArgs.address(s));
    }

    @Test
    void segmentConfinedToAnotherThreadIsRejected() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = arena.allocate(16);
            ExecutionException e = assertThrows(ExecutionException.class,
                    () -> CompletableFuture.runAsync(() -> NativeArgs.address(s)).get());
            assertInstanceOf(WrongThreadException.class, e.getCause());
        }
    }
}
