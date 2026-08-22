package com.ternbusty.takoyaki.seccomp;

import com.ternbusty.takoyaki.ipc.ScmRights;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;
import com.ternbusty.takoyaki.util.Json;

import java.lang.foreign.Arena;

/**
 * Forward a seccomp notify fd to an external listener over a Unix socket.
 *
 * Protocol (matching runc / kontainer-runtime):
 *   1. AF_UNIX SOCK_STREAM connect() to {@code listenerPath}.
 *   2. send() container state JSON + "\n" so the listener can identify the
 *      container that this fd belongs to. Optionally followed by listenerMetadata.
 *   3. sendmsg() with SCM_RIGHTS carrying the notify fd (1 dummy byte iov).
 *   4. close().
 *
 * The Unix socket connect MUST happen on the host (in CreateCommand), because the
 * listener path is a host-side file and the container's mount namespace doesn't
 * have it after pivot_root. CreateCommand calls {@link #connectHostSide} before
 * forking the bootstrap, passes the fd via env, and the init reuses it.
 */
public final class SeccompListener {
    private SeccompListener() {}

    /**
     * Open and connect a Unix socket to listenerPath on the host. Retries up
     * to 2 seconds (200ms intervals) to tolerate a listener that is still
     * starting up. Returns the connected fd, or -1 on failure.
     */
    public static int connectHostSide(String listenerPath) {
        int maxAttempts = 10;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try (Arena arena = Arena.ofConfined()) {
                int sock = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
                if (sock < 0) {
                    Logger.warn("seccomp listener socket() failed: " + Libc.strerror(Libc.errno()));
                    return -1;
                }
                if (connect(arena, sock, listenerPath)) {
                    return sock;
                }
                PosixIO.close(sock);
            }
            if (attempt < maxAttempts) {
                Logger.debug("seccomp listener not ready, retry " + attempt + "/" + maxAttempts);
                try { Thread.sleep(200); } catch (InterruptedException e) { break; }
            }
        }
        return -1;
    }

    /**
     * Forward the notify fd over a pre-connected socket. If preConnectedFd is -1,
     * fall back to connecting from here (only works pre-pivot or when the listener
     * path is somehow reachable from inside the container, which it usually isn't).
     *
     * The OCI seccomp notify protocol requires a single {@code sendmsg} carrying
     * both the {@code ContainerProcessState} JSON as the iov data and the notify
     * fd as SCM_RIGHTS ancillary data. The receiver ({@code seccompagent}) does
     * one {@code recvmsg} expecting both payloads atomically.
     */
    public static void forward(String listenerPath,
                               State state,
                               String listenerMetadata,
                               int notifyFd,
                               int preConnectedFd) {
        Logger.debug("forwarding seccomp notify fd=" + notifyFd
                + " to listener " + listenerPath
                + (preConnectedFd >= 0 ? " (via host-prepared fd " + preConnectedFd + ")" : ""));
        try (Arena arena = Arena.ofConfined()) {
            int sock;
            if (preConnectedFd >= 0) {
                sock = preConnectedFd;
            } else {
                sock = PosixIO.socket(Constants.AF_UNIX, Constants.SOCK_STREAM, 0);
                if (sock < 0) {
                    Logger.warn("seccomp listener socket() failed: " + Libc.strerror(Libc.errno()));
                    return;
                }
                if (!connect(arena, sock, listenerPath)) {
                    PosixIO.close(sock);
                    return;
                }
            }
            try {
                // Build ContainerProcessState (OCI runtime spec §linux-seccomp).
                // The receiver maps fds[] entries by index to the SCM_RIGHTS fds
                // received in the same recvmsg.
                String containerProcessState = buildContainerProcessState(
                        state, listenerMetadata);
                byte[] payload = containerProcessState.getBytes();
                if (!ScmRights.sendFdWithData(sock, notifyFd, payload)) {
                    Logger.warn("failed to send seccomp notify fd via SCM_RIGHTS");
                    return;
                }
                Logger.info("seccomp notify fd forwarded to " + listenerPath);
            } finally {
                PosixIO.close(sock);
            }
        }
    }

    /**
     * Build a ContainerProcessState JSON string matching the OCI spec.
     *
     * Structure expected by seccompagent and other compliant listeners:
     * <pre>
     * {
     *   "ociVersion": "...",
     *   "fds": ["seccompFd"],
     *   "pid": <pid>,
     *   "metadata": "...",
     *   "state": { <container state> }
     * }
     * </pre>
     */
    private static String buildContainerProcessState(State state, String metadata) {
        java.util.Map<String, Object> cps = new java.util.LinkedHashMap<>();
        cps.put("ociVersion", state.ociVersion != null ? state.ociVersion : "1.0.2");
        cps.put("fds", java.util.List.of("seccompFd"));
        cps.put("pid", state.pid != null ? state.pid : 0);
        if (metadata != null && !metadata.isEmpty()) {
            cps.put("metadata", metadata);
        }
        cps.put("state", state.toJson());
        return Json.encode(cps);
    }

    private static boolean connect(Arena arena, int sock, String path) {
        try {
            if (PosixIO.connectUnix(arena, sock, path) != 0) {
                Logger.warn("seccomp listener connect(" + path + ") failed: "
                        + Libc.strerror(Libc.errno()));
                return false;
            }
            return true;
        } catch (IllegalArgumentException e) {
            // PosixIO.connectUnix rejects paths >= 108 bytes (sun_path limit).
            Logger.warn("seccomp listener path too long: " + path);
            return false;
        }
    }

    private static boolean writeAll(Arena arena, int sock, byte[] data) {
        int off = 0;
        while (off < data.length) {
            byte[] chunk;
            if (off == 0) {
                chunk = data;
            } else {
                chunk = new byte[data.length - off];
                System.arraycopy(data, off, chunk, 0, chunk.length);
            }
            long n = PosixIO.write(arena, sock, chunk);
            if (n < 0) {
                Logger.warn("seccomp listener write failed: " + Libc.strerror(Libc.errno()));
                return false;
            }
            if (n == 0) return false;
            off += (int) n;
        }
        return true;
    }
}
