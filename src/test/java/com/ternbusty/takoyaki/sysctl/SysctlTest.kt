package com.ternbusty.takoyaki.sysctl

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Test
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

class SysctlTest {

    @Test
    fun nullMapIsNoOp() {
        mockkStatic(Files::class)
        try {
            Sysctl.apply(null)
            verify(exactly = 0) { Files.writeString(any<Path>(), any<CharSequence>()) }
        } finally {
            unmockkStatic(Files::class)
        }
    }

    @Test
    fun emptyMapIsNoOp() {
        mockkStatic(Files::class)
        try {
            Sysctl.apply(emptyMap())
            verify(exactly = 0) { Files.writeString(any<Path>(), any<CharSequence>()) }
        } finally {
            unmockkStatic(Files::class)
        }
    }

    @Test
    fun dotsInKeyAreTurnedIntoSlashes() {
        // OCI sysctl keys use dots (net.ipv4.ip_forward) but the kernel's
        // virtual files use slashes (/proc/sys/net/ipv4/ip_forward). This
        // translation is the entire job of Sysctl.apply.
        mockkStatic(Files::class)
        try {
            every { Files.writeString(any<Path>(), any<CharSequence>()) } returns Path.of("/dev/null")

            Sysctl.apply(mapOf("net.ipv4.ip_forward" to "1"))

            verify {
                Files.writeString(
                    eq(Path.of("/proc/sys/net/ipv4/ip_forward")),
                    eq("1")
                )
            }
        } finally {
            unmockkStatic(Files::class)
        }
    }

    @Test
    fun writeFailureIsLoggedNotPropagated() {
        mockkStatic(Files::class)
        try {
            every { Files.writeString(any<Path>(), any<CharSequence>()) } throws IOException("EROFS")

            // The runtime is supposed to warn and continue, not crash, when
            // a sysctl is denied (host kernel rejects, namespace forbids, ...).
            assertDoesNotThrow { Sysctl.apply(mapOf("kernel.hostname" to "foo")) }
        } finally {
            unmockkStatic(Files::class)
        }
    }

    @Test
    fun nonNamespacedKeysAreRejectedWithoutWriting() {
        // kernel.core_pattern, kernel.modprobe, vm.*, etc. are host-global.
        // A rootful container init still holds CAP_SYS_ADMIN in the initial
        // user namespace at this point, so a naive write would succeed and
        // mutate the host. The allowlist must refuse them.
        val input = linkedMapOf(
            "kernel.core_pattern" to "|/tmp/pwn.sh %P",
            "kernel.modprobe" to "/tmp/pwn.sh",
            "vm.swappiness" to "0",
            "fs.file-max" to "999999"
        )

        mockkStatic(Files::class)
        try {
            Sysctl.apply(input)
            verify(exactly = 0) { Files.writeString(any<Path>(), any<CharSequence>()) }
        } finally {
            unmockkStatic(Files::class)
        }
    }

    @Test
    fun mixedGoodAndBadOnlyWritesTheGood() {
        val input = linkedMapOf(
            "kernel.core_pattern" to "|/tmp/pwn.sh",   // rejected
            "net.ipv4.ip_forward" to "1",              // allowed
            "vm.swappiness" to "0",                    // rejected
            "fs.mqueue.msg_max" to "100"               // allowed
        )

        mockkStatic(Files::class)
        try {
            every { Files.writeString(any<Path>(), any<CharSequence>()) } returns Path.of("/dev/null")

            Sysctl.apply(input)

            verify {
                Files.writeString(
                    eq(Path.of("/proc/sys/net/ipv4/ip_forward")), eq("1")
                )
            }
            verify {
                Files.writeString(
                    eq(Path.of("/proc/sys/fs/mqueue/msg_max")), eq("100")
                )
            }
            verify(exactly = 0) {
                Files.writeString(eq(Path.of("/proc/sys/kernel/core_pattern")), any<CharSequence>())
            }
            verify(exactly = 0) {
                Files.writeString(eq(Path.of("/proc/sys/vm/swappiness")), any<CharSequence>())
            }
        } finally {
            unmockkStatic(Files::class)
        }
    }

    @Test
    fun allEntriesAreAttemptedEvenIfOneFails() {
        // Use LinkedHashMap so we control ordering of the assertions below.
        val input = linkedMapOf(
            "net.ipv4.bad_key" to "1",
            "net.ipv4.good_key" to "2"
        )

        mockkStatic(Files::class)
        try {
            every { Files.writeString(eq(Path.of("/proc/sys/net/ipv4/bad_key")), any<CharSequence>()) } throws IOException("EROFS")
            every { Files.writeString(eq(Path.of("/proc/sys/net/ipv4/good_key")), any<CharSequence>()) } returns Path.of("/dev/null")

            Sysctl.apply(input)

            // Even though the first entry threw, the loop must have attempted
            // the second one.
            verify {
                Files.writeString(
                    eq(Path.of("/proc/sys/net/ipv4/good_key")),
                    eq("2")
                )
            }
        } finally {
            unmockkStatic(Files::class)
        }
    }
}
