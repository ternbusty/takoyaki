package com.ternbusty.takoyaki.keyring

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.SyscallHost
import com.ternbusty.takoyaki.syscall.Syscalls

/**
 * Join a fresh kernel session keyring so the container can't see (or be affected by)
 * keys from the runtime's session.
 *
 *     keyctl(KEYCTL_JOIN_SESSION_KEYRING, "container-name", 0, 0, 0)
 *
 * runc does this by default; opting out via --no-new-keyring leaves the inherited
 * keyring intact.
 *
 * Done in init AFTER privilege drop but BEFORE execve. The keyring is per-thread so
 * we must run it from the thread that will exec.
 */
object Keyring {

    fun joinNewSession(name: String?) {
        val sc: Syscalls = SyscallHost.current()
        val rc = sc.keyctlJoinSessionKeyring(name)
        if (rc < 0) {
            Logger.debug("keyctl(JOIN_SESSION_KEYRING) failed: ${sc.strerror(sc.errno())}")
        } else {
            Logger.debug("joined new session keyring serial=$rc")
        }
    }
}
