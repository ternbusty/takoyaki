package com.ternbusty.takoyaki.seccomp

import com.ternbusty.takoyaki.ipc.ScmRights
import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.state.State
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import com.ternbusty.takoyaki.util.Json

import java.lang.foreign.Arena

/**
 * Forward a seccomp notify fd to an external listener over a Unix socket.
 *
 * Protocol (matching runc / kontainer-runtime):
 *   1. AF_UNIX SOCK_STREAM connect() to [listenerPath].
 *   2. send() container state JSON + "\n" so the listener can identify the
 *      container that this fd belongs to. Optionally followed by listenerMetadata.
 *   3. sendmsg() with SCM_RIGHTS carrying the notify fd (1 dummy byte iov).
 *   4. close().
 *
 * The Unix socket connect MUST happen on the host (in CreateCommand), because the
 * listener path is a host-side file and the container's mount namespace doesn't
 * have it after pivot_root. CreateCommand calls [connectHostSide] before
 * forking the bootstrap, passes the fd via env, and the init reuses it.
 */
class SeccompListener private constructor() {

    companion object {

        /**
         * Open and connect a Unix socket to listenerPath on the host. Retries up
         * to 2 seconds (200ms intervals) to tolerate a listener that is still
         * starting up. Returns the connected fd, or -1 on failure.
         */
        fun connectHostSide(listenerPath: String): Int {
            val maxAttempts = 10
            for (attempt in 1..maxAttempts) {
                Arena.ofConfined().use { arena ->
                    val sock = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0)
                    if (sock < 0) {
                        Logger.warn("seccomp listener socket() failed: ${Libc.strerror(Libc.errno())}")
                        return -1
                    }
                    if (connect(arena, sock, listenerPath)) {
                        return sock
                    }
                    PosixIO.close(sock)
                }
                if (attempt < maxAttempts) {
                    Logger.debug("seccomp listener not ready, retry $attempt/$maxAttempts")
                    try {
                        Thread.sleep(200)
                    } catch (_: InterruptedException) {
                        break
                    }
                }
            }
            return -1
        }

        /**
         * Forward the notify fd over a pre-connected socket. If preConnectedFd is -1,
         * fall back to connecting from here (only works pre-pivot or when the listener
         * path is somehow reachable from inside the container, which it usually isn't).
         *
         * The OCI seccomp notify protocol requires a single `sendmsg` carrying
         * both the `ContainerProcessState` JSON as the iov data and the notify
         * fd as SCM_RIGHTS ancillary data. The receiver (`seccompagent`) does
         * one `recvmsg` expecting both payloads atomically.
         */
        fun forward(
            listenerPath: String,
            state: State,
            listenerMetadata: String?,
            notifyFd: Int,
            preConnectedFd: Int
        ) {
            Logger.debug(
                "forwarding seccomp notify fd=$notifyFd to listener $listenerPath" +
                if (preConnectedFd >= 0) " (via host-prepared fd $preConnectedFd)" else ""
            )
            Arena.ofConfined().use { arena ->
                val sock = if (preConnectedFd >= 0) {
                    preConnectedFd
                } else {
                    val s = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0)
                    if (s < 0) {
                        Logger.warn("seccomp listener socket() failed: ${Libc.strerror(Libc.errno())}")
                        return
                    }
                    if (!connect(arena, s, listenerPath)) {
                        PosixIO.close(s)
                        return
                    }
                    s
                }
                try {
                    // Build ContainerProcessState (OCI runtime spec linux-seccomp).
                    // The receiver maps fds[] entries by index to the SCM_RIGHTS fds
                    // received in the same recvmsg.
                    val containerProcessState = buildContainerProcessState(state, listenerMetadata)
                    val payload = containerProcessState.toByteArray()
                    if (!ScmRights.sendFdWithData(sock, notifyFd, payload)) {
                        Logger.warn("failed to send seccomp notify fd via SCM_RIGHTS")
                        return
                    }
                    Logger.info("seccomp notify fd forwarded to $listenerPath")
                } finally {
                    PosixIO.close(sock)
                }
            }
        }

        /**
         * Build a ContainerProcessState JSON string matching the OCI spec.
         *
         * Structure expected by seccompagent and other compliant listeners:
         * ```
         * {
         *   "ociVersion": "...",
         *   "fds": ["seccompFd"],
         *   "pid": <pid>,
         *   "metadata": "...",
         *   "state": { <container state> }
         * }
         * ```
         */
        private fun buildContainerProcessState(state: State, metadata: String?): String {
            val cps = LinkedHashMap<String, Any>()
            cps["ociVersion"] = state.ociVersion ?: "1.0.2"
            cps["fds"] = listOf("seccompFd")
            cps["pid"] = state.pid ?: 0
            if (!metadata.isNullOrEmpty()) {
                cps["metadata"] = metadata
            }
            cps["state"] = state.toJson()
            return Json.encode(cps)
        }

        private fun connect(arena: Arena, sock: Int, path: String): Boolean =
            try {
                if (PosixIO.connectUnix(arena, sock, path) != 0) {
                    Logger.warn("seccomp listener connect($path) failed: ${Libc.strerror(Libc.errno())}")
                    false
                } else {
                    true
                }
            } catch (e: IllegalArgumentException) {
                // PosixIO.connectUnix rejects paths >= 108 bytes (sun_path limit).
                Logger.warn("seccomp listener path too long: $path")
                false
            }

        private fun writeAll(arena: Arena, sock: Int, data: ByteArray): Boolean {
            var off = 0
            while (off < data.size) {
                val chunk = if (off == 0) data else data.copyOfRange(off, data.size)
                val n = PosixIO.write(arena, sock, chunk)
                if (n < 0) {
                    Logger.warn("seccomp listener write failed: ${Libc.strerror(Libc.errno())}")
                    return false
                }
                if (n == 0L) return false
                off += n.toInt()
            }
            return true
        }
    }
}
