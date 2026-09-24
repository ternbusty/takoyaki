package com.ternbusty.takoyaki.syscall.gen;

import com.ternbusty.takoyaki.syscall.Libc;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Real downcalls through the NativeH methods written by GenerateFastBindings,
 * one fixed-arity and one of each generated variadic shape that is safe to call.
 */
class FastBindingsTest {

    private static final long PID = ProcessHandle.current().pid();

    @Test
    void fixedArityFunction() {
        assertEquals(PID, NativeH.getpid());
    }

    @Test
    void variadicSyscall() {
        assertEquals(PID, Libc.syscall(NativeH.SYS_getpid(), 0, 0, 0, 0, 0));
    }

    @Test
    void variadicPrctlRoundTripsThreadName() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocate(16);
            assertEquals(0, Libc.prctl(NativeH.PR_GET_NAME(), buf.address(), 0, 0, 0));
            String name = buf.getString(0);
            MemorySegment again = arena.allocate(16);
            assertEquals(0, Libc.prctl(NativeH.PR_SET_NAME(), arena.allocateFrom(name).address(), 0, 0, 0));
            assertEquals(0, Libc.prctl(NativeH.PR_GET_NAME(), again.address(), 0, 0, 0));
            assertEquals(name, again.getString(0));
        }
    }

    @Test
    void pointerArgumentAndReturn() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = arena.allocateFrom("takoyaki");
            assertEquals(8L, NativeH.strlen(s));
        }
    }
}
