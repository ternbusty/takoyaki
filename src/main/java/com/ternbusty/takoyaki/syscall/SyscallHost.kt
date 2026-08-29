package com.ternbusty.takoyaki.syscall

/**
 * Per-thread holder of the active [Syscalls] implementation.
 *
 * Production threads always see [LinuxSyscalls]. A test installs an
 * alternate impl with [install] and restores via the returned
 * [Scope] (try-with-resources friendly).
 *
 * Per-thread, not global, so JUnit can run test classes in parallel without
 * trampling each other's fakes.
 */
object SyscallHost {

    private val CURRENT: ThreadLocal<Syscalls> =
        ThreadLocal.withInitial(::LinuxSyscalls)

    /** Get the active impl for this thread. */
    fun current(): Syscalls = CURRENT.get()

    /**
     * Install [impl] for this thread until the returned scope is closed.
     *
     * ```
     * SyscallHost.install(RecordingSyscalls()).use {
     *     codeUnderTest()
     * }
     * ```
     */
    fun install(impl: Syscalls): Scope {
        val prev = CURRENT.get()
        CURRENT.set(impl)
        return Scope { CURRENT.set(prev) }
    }

    /** AutoCloseable without a checked exception, for use in test try-blocks. */
    fun interface Scope : AutoCloseable {
        override fun close()
    }
}
