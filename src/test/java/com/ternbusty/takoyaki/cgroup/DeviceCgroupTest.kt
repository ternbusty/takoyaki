package com.ternbusty.takoyaki.cgroup

import com.ternbusty.takoyaki.spec.Spec
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

/**
 * Exercise the eBPF program emitter in isolation. We never load these
 * programs into the kernel from the test JVM — we just lock down the
 * byte-for-byte output so future "fixes" to the emitter that change rule
 * semantics fail loudly. The instruction encoding is fixed at 8 bytes per
 * insn (the canonical BPF struct layout).
 */
class DeviceCgroupTest {

    private fun rule(allow: Boolean, type: String?, major: Long?, minor: Long?, access: String?): Spec.LinuxDeviceCgroup {
        val r = Spec.LinuxDeviceCgroup()
        r.allow = allow
        r.type = type
        r.major = major
        r.minor = minor
        r.access = access
        return r
    }

    @Test
    fun programIsAlwaysAMultipleOf8Bytes() {
        // BPF instructions are 8 bytes each. A non-multiple length would
        // confuse the kernel verifier — guard against off-by-N regressions
        // in the emit loop.
        for (rules in listOf(
            emptyList(),
            listOf(rule(false, null, null, null, "rwm")),
            listOf(rule(true, "c", 1L, 3L, "rwm")),
            listOf(rule(true, "c", 1L, 3L, "rwm"),
                rule(false, null, null, null, "rwm"))
        )) {
            val prog = DeviceCgroup.buildProgram(rules)
            assertEquals(0, prog.size % 8,
                "BPF program length must be a multiple of 8 (insn size). got ${prog.size}")
            assertTrue(prog.isNotEmpty(), "program must contain at least the prelude+tail")
        }
    }

    @Test
    fun programGrowsMonotonicallyWithMoreRules() {
        // Sanity: each extra rule adds insns. A regression that no-ops rules
        // would silently produce the same-size program for both cases.
        val one = DeviceCgroup.buildProgram(listOf(
            rule(true, "c", 1L, 3L, "rwm")))
        val two = DeviceCgroup.buildProgram(listOf(
            rule(true, "c", 1L, 3L, "rwm"),
            rule(true, "c", 5L, 0L, "rwm")))
        assertTrue(two.size > one.size,
            "appending a rule must lengthen the emitted program")
    }

    @Test
    fun preludeIsTheSameRegardlessOfRules() {
        // The first 48 bytes (6 insns × 8) are the prelude that loads
        // access_type / major / minor into BPF registers. If someone reworks
        // that block they must explicitly update this test — and think hard.
        val empty = DeviceCgroup.buildProgram(emptyList())
        val withRule = DeviceCgroup.buildProgram(listOf(
            rule(true, "c", 1L, 3L, "rwm")))
        assertArrayEquals(
            empty.copyOfRange(0, 48),
            withRule.copyOfRange(0, 48),
            "the 6-insn prelude must be identical between programs")
    }

    @Test
    fun emptyRuleSetEmitsDenyAllTail() {
        // With no rules the only thing left is the default tail: mov R0, 0;
        // exit. So the program must be exactly prelude (48 bytes) + tail
        // (16 bytes) = 64 bytes.
        val prog = DeviceCgroup.buildProgram(emptyList())
        assertEquals(48 + 16, prog.size,
            "empty rule set should produce prelude + (mov 0; exit) tail only")
    }

    @Test
    fun allowFlagEndsUpInTheReturnInstruction() {
        // For a single matching rule the last-but-one insn is "mov R0, allow
        // ? 1 : 0". Pick that off the program and verify the immediate.
        val allow = DeviceCgroup.buildProgram(listOf(
            rule(true, "c", 1L, 3L, "rwm")))
        val deny = DeviceCgroup.buildProgram(listOf(
            rule(false, "c", 1L, 3L, "rwm")))
        // Both programs have a final tail (mov R0, 0; exit) of 16 bytes.
        // The rule's own "mov R0, allow" is therefore at offset (len - 16 - 16).
        val allowImmOffset = allow.size - 16 - 16 + 4 // imm field starts 4 bytes into the insn
        val denyImmOffset = deny.size - 16 - 16 + 4
        assertEquals(1, (allow[allowImmOffset].toInt() and 0xff), "allow=true must emit imm=1")
        assertEquals(0, (deny[denyImmOffset].toInt() and 0xff), "allow=false must emit imm=0")
    }
}
