package com.ternbusty.takoyaki.keyring

import com.ternbusty.takoyaki.syscall.RecordingSyscalls
import com.ternbusty.takoyaki.syscall.SyscallHost
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Rewritten to drive the Syscalls trait fake. The previous version pinned the
 * raw keyctl syscall number / command int directly via mockStatic(Libc.class).
 * That logic now lives inside LinuxSyscalls. The fake intercepts at the
 * semantic level -- "did we ask to join a new session keyring?".
 */
class KeyringTest {

    @Test
    fun joinNewSessionInvokesKeyctlOnce() {
        // Single call per joinNewSession invocation. No retry, no fan-out.
        val rec = RecordingSyscalls().stubKeyctlJoinReturn(42L)
        SyscallHost.install(rec).use {
            Keyring.joinNewSession("takoyaki-7")
        }
        assertEquals(1, rec.keyctlJoinCalls().size)
        assertEquals("takoyaki-7", rec.keyctlJoinCalls()[0].name)
    }

    @Test
    fun anonymousSessionPassesNullName() {
        // name == null is "anonymous new session keyring" per kernel semantics.
        // We must propagate the null, NOT substitute a default string.
        val rec = RecordingSyscalls().stubKeyctlJoinReturn(0L)
        SyscallHost.install(rec).use {
            Keyring.joinNewSession(null)
        }
        assertEquals(1, rec.keyctlJoinCalls().size)
        assertNull(rec.keyctlJoinCalls()[0].name,
            "null name must pass through as null")
    }

    @Test
    fun negativeReturnIsLoggedNotPropagated() {
        // EPERM from the kernel must surface as a debug log, not a thrown
        // exception. The container should still come up.
        val rec = RecordingSyscalls()
            .stubKeyctlJoinReturn(-1L)
            .stubErrno(1 /*EPERM*/)

        SyscallHost.install(rec).use {
            assertDoesNotThrow { Keyring.joinNewSession("anything") }
        }
        assertEquals(1, rec.keyctlJoinCalls().size)
    }
}
