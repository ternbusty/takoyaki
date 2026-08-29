package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.spec.Spec
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

/**
 * Pure helpers extracted from MainProcess.run. Both contribute to the
 * uid_map/gid_map writes the kernel rejects in subtle ways if the format
 * drifts.
 */
class MainProcessHelpersTest {

    private fun map(container: Int, host: Int, size: Int): Spec.IdMapping {
        val m = Spec.IdMapping()
        m.containerID = container.toLong()
        m.hostID = host.toLong()
        m.size = size.toLong()
        return m
    }

    // ---- buildIdMapping -----------------------------------------------------

    @Test
    fun singleMappingRendersAsOneLineNoHeader() {
        // Kernel parser is strict: just "<container> <host> <size>\n", no
        // leading "#", no blank line between entries.
        val s = MainProcess.buildIdMapping(listOf(map(0, 1000, 1)), 1000)
        assertEquals("0 1000 1\n", s)
    }

    @Test
    fun multipleMappingsAreNewlineSeparated() {
        val s = MainProcess.buildIdMapping(listOf(
            map(0, 1000, 1),
            map(1, 100000, 65536)), 1000)
        assertEquals("0 1000 1\n1 100000 65536\n", s)
    }

    @Test
    fun nullMappingsFallsBackToIdentityOfCurrentUid() {
        // No mappings in spec means "trivial 1:1 identity for current euid",
        // which lets a rootless quick boot work without spec gymnastics.
        val s = MainProcess.buildIdMapping(null, 1000)
        assertEquals("0 1000 1\n", s)
    }

    @Test
    fun emptyMappingsAlsoFallsBackToIdentity() {
        val s = MainProcess.buildIdMapping(listOf(), 1000)
        assertEquals("0 1000 1\n", s)
    }

    @Test
    fun largeRangeRendersTheActualSize() {
        // Make sure we don't accidentally clamp the size value.
        val s = MainProcess.buildIdMapping(listOf(map(0, 100000, 65536)), 0)
        assertEquals("0 100000 65536\n", s)
    }

    // ---- multiRange ---------------------------------------------------------

    @Test
    fun multiRangeNullIsFalse() {
        // A null mapping list goes through the direct-write path with the
        // fallback "0 <euid> 1\n", which is trivially writable.
        assertFalse(MainProcess.multiRange(null))
    }

    @Test
    fun multiRangeEmptyListIsFalse() {
        assertFalse(MainProcess.multiRange(listOf()))
    }

    @Test
    fun multiRangeSingleEntrySizeOneIsFalse() {
        // The narrow "rootless quick boot" case: just one 1-row mapping.
        // The kernel accepts that as a direct write.
        assertFalse(MainProcess.multiRange(listOf(map(0, 1000, 1))))
    }

    @Test
    fun multiRangeSingleEntrySizeAboveOneIsTrue() {
        // A 65536-wide range needs newuidmap (setuid helper); writing directly
        // is rejected by the kernel without CAP_SETUID.
        assertTrue(MainProcess.multiRange(listOf(map(0, 100000, 65536))))
    }

    @Test
    fun multiRangeTwoEntriesIsTrueRegardlessOfSize() {
        // Multiple entries also need the helper.
        assertTrue(MainProcess.multiRange(listOf(
            map(0, 1000, 1),
            map(1, 1001, 1))))
    }
}
