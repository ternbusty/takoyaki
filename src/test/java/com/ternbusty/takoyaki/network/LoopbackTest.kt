package com.ternbusty.takoyaki.network

import com.ternbusty.takoyaki.syscall.RecordingSyscalls
import com.ternbusty.takoyaki.syscall.SyscallHost
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

/**
 * Loopback.up() is one line of semantic intent now ("bring lo up"). The
 * ioctl dance moved into LinuxSyscalls.ifUp(). So all the tests boil down
 * to: did the caller ask for "lo", and is failure swallowed.
 *
 * The "what if SIOCGIFFLAGS fails / what if socket fails" cases are at the
 * LinuxSyscalls layer and validated by the integration suite — they're not
 * unit-testable here without re-mocking the whole ioctl ABI.
 */
class LoopbackTest {

    @Test
    fun upRequestsIfUpForLo() {
        // The CORE contract: Loopback exists to bring "lo" up specifically,
        // not "eth0" or "any". A typo here breaks every container's localhost.
        val rec = RecordingSyscalls().stubIfUpReturn(0)
        SyscallHost.install(rec).use {
            Loopback.up()
        }

        assertEquals(
            listOf(RecordingSyscalls.IfUpCall("lo")),
            rec.ifUpCalls()
        )
    }

    @Test
    fun ifUpFailureIsLoggedNotThrown() {
        // Failure (e.g. CAP_NET_ADMIN missing in rootless) must NOT bubble
        // up. The container should still come up, just without working lo.
        val rec = RecordingSyscalls()
            .stubIfUpReturn(-1)
            .stubErrno(1 /*EPERM*/)
        SyscallHost.install(rec).use {
            assertDoesNotThrow { Loopback.up() }
        }
    }
}
