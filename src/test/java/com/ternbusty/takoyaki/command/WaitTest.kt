package com.ternbusty.takoyaki.command

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertEquals

/**
 * decodeStatus() translates the wait(2) raw status into a shell-style exit code.
 * Getting the bit layout wrong here means `takoyaki exec` reports nonsense
 * exit codes that confuse shells and CI.
 *
 * Linux status word layout (see waitstatus.h):
 *   bits 6..0   = terminating signal (0 if process exited normally)
 *   bit 7       = core dumped flag
 *   bits 15..8  = WEXITSTATUS  (low byte of exit())
 */
class WaitTest {

    @Test
    fun exit0DecodesToZero() {
        // Normal `exit(0)`: low byte clear, exit byte = 0.
        assertEquals(0, Wait.decodeStatus(0x0000))
    }

    @Test
    fun exit1DecodesToOne() {
        // `exit(1)` -> raw word 0x0100.
        assertEquals(1, Wait.decodeStatus(0x0100))
    }

    @Test
    fun exit42DecodesTo42() {
        assertEquals(42, Wait.decodeStatus(42 shl 8))
    }

    @Test
    fun exit255DecodesTo255AndMaskedTo8Bits() {
        // Anything above 255 is masked off, matching glibc's WEXITSTATUS macro.
        assertEquals(255, Wait.decodeStatus(0xFF00))
    }

    @Test
    fun exitStatusUpperBitsAreIgnored() {
        // Bits 16..31 of the raw word are kernel padding. We must mask to 8 bits.
        // 0xABCDFF00 -> 0xFF -> 255
        assertEquals(255, Wait.decodeStatus(0xABCD_FF00.toInt()))
    }

    @Test
    fun killedBySigtermDecodesTo128Plus15() {
        // SIGTERM=15. Per POSIX shell convention, signal death = 128+signo.
        // Raw: low 7 bits = 15.
        assertEquals(128 + 15, Wait.decodeStatus(15))
    }

    @Test
    fun killedBySigkillDecodesTo137() {
        // SIGKILL=9 -> 137.
        assertEquals(137, Wait.decodeStatus(9))
    }

    @Test
    fun coreDumpedFlagDoesNotAffectExitCode() {
        // bit 7 (= 0x80) is the "core dumped" flag. It must NOT bleed into the
        // returned code — we only look at bits 0..6 for the signal.
        // SIGSEGV=11 + core flag = 0x8b. Expect 128+11=139.
        assertEquals(128 + 11, Wait.decodeStatus(0x8b))
    }
}
