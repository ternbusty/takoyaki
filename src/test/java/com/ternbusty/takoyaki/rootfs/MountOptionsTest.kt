package com.ternbusty.takoyaki.rootfs

import com.ternbusty.takoyaki.syscall.Constants
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MountOptionsTest {

    @Test
    fun nullOptionsReturnZerosAndNullData() {
        // A mount entry without options must not blow up the parser. All buckets
        // come back zeroed.
        val p = MountOptions.parse(null)
        assertEquals(0L, p.flags)
        assertEquals(0L, p.propagation)
        assertNull(p.data)
        assertFalse(p.isBind)
    }

    @Test
    fun emptyOptionsReturnZerosAndNullData() {
        val p = MountOptions.parse(listOf())
        assertEquals(0L, p.flags)
        assertEquals(0L, p.propagation)
        assertNull(p.data)
        assertFalse(p.isBind)
    }

    @Test
    fun bindFlagsIsBindAndSetsMsBind() {
        val p = MountOptions.parse(listOf("bind"))
        assertEquals(Constants.MS_BIND, p.flags)
        assertTrue(p.isBind, "isBind must be true so the caller knows to skip type")
    }

    @Test
    fun rbindIsBindAndImpliesRec() {
        // rbind = recursive bind, both MS_BIND and MS_REC must be set.
        val p = MountOptions.parse(listOf("rbind"))
        assertEquals(Constants.MS_BIND or Constants.MS_REC, p.flags)
        assertTrue(p.isBind)
    }

    @Test
    fun accessFlagsAllCombineWithOr() {
        // ro+nosuid+nodev+noexec is the standard lock-down recipe for a bind.
        val p = MountOptions.parse(listOf("ro", "nosuid", "nodev", "noexec"))
        val expected = Constants.MS_RDONLY or Constants.MS_NOSUID or
                Constants.MS_NODEV or Constants.MS_NOEXEC
        assertEquals(expected, p.flags)
        assertEquals(0L, p.propagation)
        assertNull(p.data)
        assertFalse(p.isBind)
    }

    @Test
    fun atimeVariantsMapToCorrectBits() {
        assertEquals(Constants.MS_NOATIME, MountOptions.parse(listOf("noatime")).flags)
        assertEquals(Constants.MS_RELATIME, MountOptions.parse(listOf("relatime")).flags)
        assertEquals(Constants.MS_STRICTATIME, MountOptions.parse(listOf("strictatime")).flags)
    }

    @Test
    fun nosymfollowAndRecMapToTheirOwnBits() {
        assertEquals(Constants.MS_NOSYMFOLLOW, MountOptions.parse(listOf("nosymfollow")).flags)
        assertEquals(Constants.MS_REC, MountOptions.parse(listOf("rec")).flags)
    }

    @Test
    fun propagationSharedSlavePrivateUnbindable() {
        // Propagation goes into its OWN bucket. Never mixed with flags. Because
        // the kernel rejects propagation combined with regular mount flags.
        assertEquals(Constants.MS_SHARED, MountOptions.parse(listOf("shared")).propagation)
        assertEquals(Constants.MS_SLAVE, MountOptions.parse(listOf("slave")).propagation)
        assertEquals(Constants.MS_PRIVATE, MountOptions.parse(listOf("private")).propagation)
        assertEquals(Constants.MS_UNBINDABLE, MountOptions.parse(listOf("unbindable")).propagation)
    }

    @Test
    fun recursivePropagationAddsMsRec() {
        assertEquals(
            Constants.MS_SHARED or Constants.MS_REC,
            MountOptions.parse(listOf("rshared")).propagation
        )
        assertEquals(
            Constants.MS_SLAVE or Constants.MS_REC,
            MountOptions.parse(listOf("rslave")).propagation
        )
        assertEquals(
            Constants.MS_PRIVATE or Constants.MS_REC,
            MountOptions.parse(listOf("rprivate")).propagation
        )
        assertEquals(
            Constants.MS_UNBINDABLE or Constants.MS_REC,
            MountOptions.parse(listOf("runbindable")).propagation
        )
    }

    @Test
    fun propagationFlagsDoNotLeakIntoFlags() {
        // Critical contract. The caller fires propagation via a SECOND mount(2)
        // call, so it must NOT appear in the flags bucket.
        val p = MountOptions.parse(listOf("rshared"))
        assertEquals(0L, p.flags)
        assertEquals(Constants.MS_SHARED or Constants.MS_REC, p.propagation)
    }

    @Test
    fun lastPropagationWins() {
        // Two propagation tokens in one option list is malformed but well-defined.
        // The parser keeps the latest, matching how Rootfs.applyOciMounts used to
        // behave with its inline switch.
        val p = MountOptions.parse(listOf("shared", "private"))
        assertEquals(Constants.MS_PRIVATE, p.propagation)
    }

    @Test
    fun unknownTokensFallThroughToDataString() {
        // Anything we don't recognize is fs-specific data ("mode=755", "size=64k").
        val p = MountOptions.parse(listOf("mode=755", "size=64k", "uid=1000"))
        assertEquals(0L, p.flags)
        assertEquals(0L, p.propagation)
        assertEquals("mode=755,size=64k,uid=1000", p.data)
    }

    @Test
    fun mixedKnownAndUnknownOnlyDataInDataString() {
        // Known tokens go to flags, unknown tokens get joined into data.
        val p = MountOptions.parse(listOf("nosuid", "mode=755", "noexec", "size=64k"))
        assertEquals(Constants.MS_NOSUID or Constants.MS_NOEXEC, p.flags)
        assertEquals("mode=755,size=64k", p.data)
    }

    @Test
    fun singleUnknownTokenHasNoCommaPrefix() {
        // Regression. An early bug joined with ",foo" when the list was empty.
        val p = MountOptions.parse(listOf("mode=755"))
        assertEquals("mode=755", p.data)
    }

    @Test
    fun typicalTmpfsRecipeProducesExpectedShape() {
        // Tmpfs mounts in real bundles look like ["nosuid","strictatime","mode=755","size=65536k"].
        val p = MountOptions.parse(listOf("nosuid", "strictatime", "mode=755", "size=65536k"))
        assertEquals(Constants.MS_NOSUID or Constants.MS_STRICTATIME, p.flags)
        assertEquals(0L, p.propagation)
        assertEquals("mode=755,size=65536k", p.data)
        assertFalse(p.isBind)
    }

    @Test
    fun typicalReadonlyRbindRecipe() {
        // Lockdown bind. rbind + ro + nosuid + nodev. isBind must be true.
        val p = MountOptions.parse(listOf("rbind", "ro", "nosuid", "nodev"))
        assertEquals(
            Constants.MS_BIND or Constants.MS_REC or
                    Constants.MS_RDONLY or Constants.MS_NOSUID or Constants.MS_NODEV,
            p.flags
        )
        assertTrue(p.isBind)
        assertNull(p.data)
    }
}
