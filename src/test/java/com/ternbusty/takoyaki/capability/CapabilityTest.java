package com.ternbusty.takoyaki.capability;

import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CapabilityTest {

    @Test
    void idOfReturnsKnownIds() {
        // OCI capabilities are spelled as CAP_*. We must agree with the kernel
        // numbering so capset / PR_CAPBSET_DROP / PR_CAP_AMBIENT_RAISE target
        // the right bit. Pin a few well-known ones.
        assertEquals(0,  Capability.idOf("CAP_CHOWN"));
        assertEquals(1,  Capability.idOf("CAP_DAC_OVERRIDE"));
        assertEquals(5,  Capability.idOf("CAP_KILL"));
        assertEquals(21, Capability.idOf("CAP_SYS_ADMIN"));
        assertEquals(-1, Capability.idOf("CAP_BOGUS"),
                "unknown cap name returns -1 (sentinel checked by callers)");
        assertEquals(-1, Capability.idOf(null));
    }

    @Test
    void setKeepCapsCallsPrctlOne() {
        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            lm.when(() -> Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()))
                    .thenReturn(0);
            Capability.setKeepCaps();
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_SET_KEEPCAPS), eq(1L), eq(0L), eq(0L), eq(0L)));
        }
    }

    @Test
    void clearKeepCapsCallsPrctlZero() {
        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            lm.when(() -> Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()))
                    .thenReturn(0);
            Capability.clearKeepCaps();
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_SET_KEEPCAPS), eq(0L), eq(0L), eq(0L), eq(0L)));
        }
    }

    @Test
    void applyBoundingSetIsNoOpForNullSpec() {
        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            Capability.applyBoundingSet(null);
            lm.verifyNoInteractions();
        }
    }

    @Test
    void applyBoundingSetIsNoOpWhenBoundingNotSpecified() {
        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            Spec.LinuxCapabilities caps = new Spec.LinuxCapabilities();
            // bounding == null
            Capability.applyBoundingSet(caps);
            lm.verifyNoInteractions();
        }
    }

    @Test
    void applyBoundingSetDropsEverythingNotListed() {
        // The bounding set contract: ANY cap not in spec.bounding must be
        // PR_CAPBSET_DROP'd. Verify we drop the ones outside the list AND
        // never drop the ones we kept.
        Spec.LinuxCapabilities caps = new Spec.LinuxCapabilities();
        caps.bounding = List.of("CAP_CHOWN", "CAP_KILL"); // ids 0 and 5

        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            lm.when(() -> Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()))
                    .thenReturn(0);
            Capability.applyBoundingSet(caps);

            // 0 (CHOWN) and 5 (KILL) must NOT be dropped.
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAPBSET_DROP), eq(0L), anyLong(), anyLong(), anyLong()),
                    never());
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAPBSET_DROP), eq(5L), anyLong(), anyLong(), anyLong()),
                    never());
            // 1 (DAC_OVERRIDE) and 21 (SYS_ADMIN) must be dropped.
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAPBSET_DROP), eq(1L), eq(0L), eq(0L), eq(0L)));
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAPBSET_DROP), eq(21L), eq(0L), eq(0L), eq(0L)));
        }
    }

    @Test
    void applyBoundingSetIgnoresUnknownCapNames() {
        // An unknown cap name in spec must NOT poison the loop or accidentally
        // KEEP every cap (id=-1 → not in keep set → everything dropped, which
        // is the safe failure mode we want).
        Spec.LinuxCapabilities caps = new Spec.LinuxCapabilities();
        caps.bounding = List.of("CAP_BOGUS");

        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            lm.when(() -> Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()))
                    .thenReturn(0);
            Capability.applyBoundingSet(caps);
            // CAP_CHOWN (id 0) must be dropped because the bogus name didn't
            // make it into the keep set.
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAPBSET_DROP), eq(0L), eq(0L), eq(0L), eq(0L)));
        }
    }

    @Test
    void applyFinalSetsCallsCapsetSyscall() {
        // applyFinalSets builds eff/per/inh bit masks and hands them to
        // syscall(NR_capset, ...). Validate the call happens for a non-empty
        // spec.
        Spec.LinuxCapabilities caps = new Spec.LinuxCapabilities();
        caps.effective   = List.of("CAP_CHOWN");
        caps.permitted   = List.of("CAP_CHOWN");
        caps.inheritable = List.of();

        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            lm.when(() -> Libc.syscall(anyLong(), anyLong(), anyLong(),
                                       anyLong(), anyLong(), anyLong())).thenReturn(0L);
            Capability.applyFinalSets(caps);
            lm.verify(() -> Libc.syscall(
                    eq((long) Constants.NR_capset),
                    anyLong(), anyLong(), eq(0L), eq(0L), eq(0L)));
        }
    }

    @Test
    void applyFinalSetsAmbientClearsThenRaisesEachListedCap() {
        // The kernel requires an ambient cap to also be in both permitted
        // AND inheritable. Reflect a valid spec so the pre-check in
        // applyFinalSets actually lets the RAISE call through.
        Spec.LinuxCapabilities caps = new Spec.LinuxCapabilities();
        caps.effective   = List.of("CAP_KILL");
        caps.permitted   = List.of("CAP_KILL");
        caps.inheritable = List.of("CAP_KILL");
        caps.ambient     = List.of("CAP_KILL"); // id 5

        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            lm.when(() -> Libc.syscall(anyLong(), anyLong(), anyLong(),
                                       anyLong(), anyLong(), anyLong())).thenReturn(0L);
            lm.when(() -> Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()))
                    .thenReturn(0);

            Capability.applyFinalSets(caps);

            // First clear ALL ambient caps.
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAP_AMBIENT),
                    eq((long) Constants.PR_CAP_AMBIENT_CLEAR_ALL),
                    eq(0L), eq(0L), eq(0L)));
            // Then raise the requested ones (CAP_KILL = 5).
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAP_AMBIENT),
                    eq((long) Constants.PR_CAP_AMBIENT_RAISE),
                    eq(5L), eq(0L), eq(0L)));
        }
    }

    @Test
    void applyFinalSetsSkipsAmbientRaiseWhenPermittedOrInheritableMissing() {
        // Spec asks for ambient=[CAP_KILL] but doesn't put CAP_KILL in
        // permitted+inheritable. The pre-check must skip the RAISE (kernel
        // would reject it anyway) and warn instead, leaving CLEAR_ALL as
        // the only ambient prctl call.
        Spec.LinuxCapabilities caps = new Spec.LinuxCapabilities();
        caps.effective = caps.permitted = caps.inheritable = List.of();
        caps.ambient = List.of("CAP_KILL");

        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            lm.when(() -> Libc.syscall(anyLong(), anyLong(), anyLong(),
                                       anyLong(), anyLong(), anyLong())).thenReturn(0L);
            lm.when(() -> Libc.prctl(anyInt(), anyLong(), anyLong(), anyLong(), anyLong()))
                    .thenReturn(0);

            Capability.applyFinalSets(caps);

            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAP_AMBIENT),
                    eq((long) Constants.PR_CAP_AMBIENT_CLEAR_ALL),
                    eq(0L), eq(0L), eq(0L)));
            // The RAISE must NOT be invoked for CAP_KILL — no per/inh backing.
            lm.verify(() -> Libc.prctl(
                    eq(Constants.PR_CAP_AMBIENT),
                    eq((long) Constants.PR_CAP_AMBIENT_RAISE),
                    anyLong(), anyLong(), anyLong()), never());
        }
    }

    @Test
    void applyFinalSetsHandlesNullSpec() {
        try (MockedStatic<Libc> lm = mockStatic(Libc.class)) {
            Capability.applyFinalSets(null);
            lm.verifyNoInteractions();
        }
    }
}
