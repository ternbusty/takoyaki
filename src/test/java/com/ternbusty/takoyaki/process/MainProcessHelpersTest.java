package com.ternbusty.takoyaki.process;

import com.ternbusty.takoyaki.spec.Spec;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure helpers extracted from MainProcess.run. Both contribute to the
 * uid_map/gid_map writes the kernel rejects in subtle ways if the format
 * drifts.
 */
class MainProcessHelpersTest {

    private static Spec.IdMapping map(int container, int host, int size) {
        Spec.IdMapping m = new Spec.IdMapping();
        m.containerID = container;
        m.hostID = host;
        m.size = size;
        return m;
    }

    // ---- buildIdMapping -----------------------------------------------------

    @Test
    void singleMappingRendersAsOneLineNoHeader() {
        // Kernel parser is strict: just "<container> <host> <size>\n", no
        // leading "#", no blank line between entries.
        String s = MainProcess.buildIdMapping(List.of(map(0, 1000, 1)), 1000);
        assertEquals("0 1000 1\n", s);
    }

    @Test
    void multipleMappingsAreNewlineSeparated() {
        String s = MainProcess.buildIdMapping(List.of(
                map(0, 1000, 1),
                map(1, 100000, 65536)), 1000);
        assertEquals("0 1000 1\n1 100000 65536\n", s);
    }

    @Test
    void nullMappingsFallsBackToIdentityOfCurrentUid() {
        // No mappings in spec means "trivial 1:1 identity for current euid",
        // which lets a rootless quick boot work without spec gymnastics.
        String s = MainProcess.buildIdMapping(null, 1000);
        assertEquals("0 1000 1\n", s);
    }

    @Test
    void emptyMappingsAlsoFallsBackToIdentity() {
        String s = MainProcess.buildIdMapping(List.of(), 1000);
        assertEquals("0 1000 1\n", s);
    }

    @Test
    void largeRangeRendersTheActualSize() {
        // Make sure we don't accidentally clamp the size value.
        String s = MainProcess.buildIdMapping(List.of(map(0, 100000, 65536)), 0);
        assertEquals("0 100000 65536\n", s);
    }

    // ---- multiRange ---------------------------------------------------------

    @Test
    void multiRangeNullIsFalse() {
        // A null mapping list goes through the direct-write path with the
        // fallback "0 <euid> 1\n", which is trivially writable.
        assertFalse(MainProcess.multiRange(null));
    }

    @Test
    void multiRangeEmptyListIsFalse() {
        assertFalse(MainProcess.multiRange(List.of()));
    }

    @Test
    void multiRangeSingleEntrySizeOneIsFalse() {
        // The narrow "rootless quick boot" case: just one 1-row mapping.
        // The kernel accepts that as a direct write.
        assertFalse(MainProcess.multiRange(List.of(map(0, 1000, 1))));
    }

    @Test
    void multiRangeSingleEntrySizeAboveOneIsTrue() {
        // A 65536-wide range needs newuidmap (setuid helper); writing directly
        // is rejected by the kernel without CAP_SETUID.
        assertTrue(MainProcess.multiRange(List.of(map(0, 100000, 65536))));
    }

    @Test
    void multiRangeTwoEntriesIsTrueRegardlessOfSize() {
        // Multiple entries also need the helper.
        assertTrue(MainProcess.multiRange(List.of(
                map(0, 1000, 1),
                map(1, 1001, 1))));
    }
}
