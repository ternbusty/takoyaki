package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout

/**
 * Minimal waitpid wrapper for foreground subcommands like `exec`. Public so
 * the process-side half of exec (ExecProcess) shares the same status
 * decoding and the two exit-code paths cannot drift.
 */
object Wait {

    fun waitForChild(pid: Int): Int {
        try {
            Arena.ofConfined().use { arena ->
                val status = arena.allocate(ValueLayout.JAVA_INT)
                var rc: Int
                do {
                    rc = Libc.waitpid(pid, status, 0)
                } while (rc < 0 && Libc.errno() == Constants.EINTR)
                if (rc < 0) return 1
                val s = status.get(ValueLayout.JAVA_INT, 0)
                return decodeStatus(s)
            }
        } catch (t: Throwable) {
            return 1
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
     * Internal for unit tests.
     */
    internal fun decodeStatus(s: Int): Int =
        if ((s and 0x7f) == 0) (s shr 8) and 0xff
        else 128 + (s and 0x7f)
}
