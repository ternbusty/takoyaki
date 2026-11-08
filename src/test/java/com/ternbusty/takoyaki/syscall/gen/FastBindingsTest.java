package com.ternbusty.takoyaki.syscall.gen;

import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real downcalls through the NativeH methods written by GenerateFastBindings,
 * one fixed-arity and one of each generated variadic shape that is safe to call,
 * and the sockaddr union arguments of bind, connect and accept.
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
    void sockaddrUnionArguments(@TempDir Path dir) {
        String path = dir.resolve("s").toString();
        int server = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
        int client = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
        try (Arena arena = Arena.ofConfined()) {
            assertEquals(0, PosixIO.bindUnix(arena, server, path));
            assertEquals(0, PosixIO.listen(server, 1));
            assertEquals(0, PosixIO.connectUnix(arena, client, path));
            int conn = PosixIO.accept(server);
            assertTrue(conn >= 0, "accept failed: errno " + Libc.errno());
            PosixIO.close(conn);
        } finally {
            PosixIO.close(client);
            PosixIO.close(server);
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
