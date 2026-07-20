package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Minimal waitpid wrapper for foreground subcommands like `exec`. Public so
 * the process-side half of exec (ExecProcess) shares the same status
 * decoding and the two exit-code paths cannot drift.
 */
public final class Wait {
    private Wait() {}

    public static int waitForChild(int pid) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment status = arena.allocate(ValueLayout.JAVA_INT);
            int rc;
            do {
                rc = Libc.waitpid(pid, status, 0);
            } while (rc < 0 && Libc.errno() == Constants.EINTR);
            if (rc < 0) return 1;
            int s = status.get(ValueLayout.JAVA_INT, 0);
            return decodeStatus(s);
        } catch (Throwable t) {
            return 1;
        }
    }

    /**
     * Translate a waitpid(2) raw status word into a shell-style exit code.
     *
     * Normal exit: low byte is 0 and the exit status sits in the next byte
     *   (WIFEXITED true, return WEXITSTATUS).
     * Signal: low 7 bits hold the terminating signal
     *   (WIFEXITED false, return 128 + signal per POSIX shell convention).
     *
     * Package-visible so the unit test can pin the bit layout without forking.
     */
    static int decodeStatus(int s) {
        if ((s & 0x7f) == 0) return (s >> 8) & 0xff;
        return 128 + (s & 0x7f);
    }
}
