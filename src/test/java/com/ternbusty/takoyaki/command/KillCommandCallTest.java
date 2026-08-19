package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls;
import com.ternbusty.takoyaki.syscall.RecordingSyscalls.KillCall;
import com.ternbusty.takoyaki.syscall.SyscallHost;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Drives the full {@link KillCommand#run} method with {@link State#load}
 * mocked and kill(2) routed through the Syscalls trait fake. We exercise the
 * actual control flow (state load -> status check -> pid presence -> signal
 * parse -> kill -> ESRCH tolerance) without touching the real OS.
 */
class KillCommandCallTest {

    private static final String ROOT = "/run/takoyaki";

    /** Build a State with the given status+pid without touching disk. */
    private State runningState(int pid) {
        State s = new State();
        s.id = "id";
        s.status = ContainerStatus.RUNNING.value;
        s.pid = pid;
        s.bundle = "/bundle";
        return s;
    }

    @Test
    void killRunningContainerCallsKillWithRightSignal() {
        State st = spy(runningState(4242));
        doReturn(st).when(st).refreshStatus();

        RecordingSyscalls rec = new RecordingSyscalls();
        try (MockedStatic<State> sm = mockStatic(State.class);
             var scope = SyscallHost.install(rec)) {
            sm.when(() -> State.load(ROOT, "ctr-a")).thenReturn(st);

            int rc = KillCommand.run(ROOT, "ctr-a", "SIGTERM", false);

            assertEquals(0, rc);
            assertEquals(List.of(new KillCall(4242, Constants.SIGTERM)),
                    rec.killCalls());
        }
    }

    @Test
    void killOnStoppedContainerReturnsErrorWithoutCallingKill() {
        State st = spy(runningState(4242));
        st.status = ContainerStatus.STOPPED.value;
        doReturn(st).when(st).refreshStatus();

        RecordingSyscalls rec = new RecordingSyscalls();
        try (MockedStatic<State> sm = mockStatic(State.class);
             var scope = SyscallHost.install(rec)) {
            sm.when(() -> State.load(anyString(), anyString())).thenReturn(st);

            int rc = KillCommand.run(ROOT, "ctr-a", "KILL", false);

            assertEquals(1, rc, "OCI spec: kill on stopped MUST error");
            assertTrue(rec.killCalls().isEmpty(),
                    "must not invoke kill(2) on stopped container");
        }
    }

    @Test
    void esrchFromKernelIsTolerated() {
        // If the process died between refreshStatus and kill(2), the kernel
        // returns ESRCH. Per runc semantics we treat that as success.
        State st = spy(runningState(4242));
        doReturn(st).when(st).refreshStatus();

        RecordingSyscalls rec = new RecordingSyscalls()
                .stubKillReturn(-1)
                .stubErrno(Constants.ESRCH);

        try (MockedStatic<State> sm = mockStatic(State.class);
             var scope = SyscallHost.install(rec)) {
            sm.when(() -> State.load(anyString(), anyString())).thenReturn(st);

            int rc = KillCommand.run(ROOT, "ctr-a", "KILL", false);

            assertEquals(0, rc, "ESRCH from kill(2) must NOT propagate as a runtime error");
            assertEquals(1, rec.killCalls().size());
        }
    }

    @Test
    void nonEsrchKillFailurePropagates() {
        State st = spy(runningState(4242));
        doReturn(st).when(st).refreshStatus();

        RecordingSyscalls rec = new RecordingSyscalls()
                .stubKillReturn(-1)
                .stubErrno(1 /* EPERM */);

        try (MockedStatic<State> sm = mockStatic(State.class);
             var scope = SyscallHost.install(rec)) {
            sm.when(() -> State.load(anyString(), anyString())).thenReturn(st);

            int rc = KillCommand.run(ROOT, "ctr-a", "KILL", false);

            assertEquals(1, rc, "non-ESRCH kill errors must surface as exit 1");
        }
    }

    @Test
    void invalidSignalNameReturnsErrorBeforeAnyKill() {
        State st = spy(runningState(4242));
        doReturn(st).when(st).refreshStatus();

        RecordingSyscalls rec = new RecordingSyscalls();
        try (MockedStatic<State> sm = mockStatic(State.class);
             var scope = SyscallHost.install(rec)) {
            sm.when(() -> State.load(anyString(), anyString())).thenReturn(st);

            int rc = KillCommand.run(ROOT, "ctr-a", "TOTALLY_NOT_A_SIGNAL", false);

            assertEquals(1, rc);
            assertTrue(rec.killCalls().isEmpty());
        }
    }

    @Test
    void missingPidIsAnError() {
        State st = spy(runningState(4242));
        st.pid = null;
        doReturn(st).when(st).refreshStatus();

        RecordingSyscalls rec = new RecordingSyscalls();
        try (MockedStatic<State> sm = mockStatic(State.class);
             var scope = SyscallHost.install(rec)) {
            sm.when(() -> State.load(anyString(), anyString())).thenReturn(st);

            int rc = KillCommand.run(ROOT, "ctr-a", "KILL", false);

            assertEquals(1, rc);
            assertTrue(rec.killCalls().isEmpty());
        }
    }

    @Test
    void stateLoadFailureReturnsErrorWithoutKill() {
        RecordingSyscalls rec = new RecordingSyscalls();
        try (MockedStatic<State> sm = mockStatic(State.class);
             var scope = SyscallHost.install(rec)) {
            sm.when(() -> State.load(anyString(), anyString()))
                    .thenThrow(new java.io.IOException("no state.json"));

            int rc = KillCommand.run(ROOT, "ctr-a", "KILL", false);

            assertEquals(1, rc);
            assertTrue(rec.killCalls().isEmpty());
        }
    }
}
