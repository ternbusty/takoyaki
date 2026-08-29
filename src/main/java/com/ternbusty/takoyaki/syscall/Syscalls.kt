package com.ternbusty.takoyaki.syscall

/**
 * Abstraction over every kernel-touching call takoyaki makes.
 *
 * This is the Java analogue of youki's `Syscall` trait. Production code
 * never calls [Libc] or [PosixIO] statics directly; it goes
 * through [SyscallHost.current] and gets either [LinuxSyscalls]
 * (real path) or [com.ternbusty.takoyaki.syscall.RecordingSyscalls]
 * (test fake that captures every call).
 *
 * The benefit over Mockito `mockStatic` is that fork/clone3/unshare-driven
 * paths become unit-testable: the fake records "we called unshare(CLONE_NEWNS)"
 * without actually unsharing the test JVM. The downside is every callsite has
 * to be migrated. We grow this interface as more callsites move over.
 *
 * Method shape: take plain Java types, never expose [java.lang.foreign.Arena].
 * Implementations handle Arena lifetime internally.
 */
interface Syscalls {

    // ---- mount(2) family ----------------------------------------------------

    /**
     * Wrap mount(2). [source] or [data] may be null; pass through
     * as NULL in that case. Returns 0 on success, -1 on failure (errno set).
     */
    fun mount(source: String?, target: String, fstype: String?, flags: Long, data: String?): Int

    /** Wrap umount2(2). */
    fun umount2(target: String, flags: Int): Int

    // ---- errno reporting ----------------------------------------------------

    /** Last syscall errno seen by THIS Syscalls impl. */
    fun errno(): Int

    /** Human-readable name for an errno value. */
    fun strerror(errnum: Int): String

    // ---- signals ------------------------------------------------------------

    /** kill(pid, sig). Returns 0 on success, -1 on failure. */
    fun kill(pid: Int, sig: Int): Int

    // ---- raw syscall --------------------------------------------------------

    /**
     * Raw syscall(2). Used for kernel calls that don't have glibc wrappers
     * (keyctl, etc). Argument count is fixed at 5 to keep the fake simple.
     */
    fun syscall(nr: Long, a1: Long, a2: Long, a3: Long, a4: Long, a5: Long): Long

    // ---- resource limits ----------------------------------------------------

    /**
     * prlimit64(pid, resource, soft, hard). Sets a single rlimit on the target
     * pid. Resource is the RLIMIT_* int (caller maps OCI strings -> int).
     */
    fun prlimit64(pid: Int, resource: Int, soft: Long, hard: Long): Int

    // ---- network interface --------------------------------------------------

    /**
     * Bring a network interface up by adding IFF_UP via SIOCGIFFLAGS /
     * SIOCSIFFLAGS. Implementations encapsulate the ioctl dance so callers
     * (Loopback, future bridge setup) only express intent.
     */
    fun ifUp(ifaceName: String): Int

    // ---- keyring ------------------------------------------------------------

    /**
     * keyctl(KEYCTL_JOIN_SESSION_KEYRING, name). Returns the new keyring
     * serial on success, -1 on failure.
     */
    fun keyctlJoinSessionKeyring(name: String?): Long

    // ---- file system primitives --------------------------------------------

    /**
     * mknod(path, mode, dev). [mode] carries both the type bits
     * (S_IFCHR / S_IFBLK / S_IFIFO) and the permission bits. Returns 0 on
     * success, -1 on failure (EPERM in user namespaces is the common one).
     */
    fun mknod(path: String, mode: Int, dev: Long): Int

    /**
     * access(path, mode). Used to probe device-node presence on the host
     * before falling back to a bind mount. Returns 0 if accessible.
     */
    fun access(path: String, mode: Int): Int
}
