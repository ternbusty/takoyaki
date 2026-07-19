package com.ternbusty.takoyaki.command;

import com.ternbusty.takoyaki.ipc.NotifySocket;
import com.ternbusty.takoyaki.state.ContainerStatus;
import com.ternbusty.takoyaki.state.State;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class StartCommandTest {

    private static final String ROOT = "/run/takoyaki";

    private State createdState() {
        State s = new State();
        s.id = "ctr-a";
        s.status = ContainerStatus.CREATED.value;
        s.pid = 4242;
        s.bundle = "/tmp/bundle";
        return s;
    }

    @Test
    void startingCreatedContainerSendsNotifyAndPersistsRunning() throws IOException {
        State st = spy(createdState());
        doReturn(st).when(st).refreshStatus();
        // withStatus(RUNNING) must return a State whose save() is harmless in
        // tests — spy it.
        State updated = spy(createdState());
        updated.status = ContainerStatus.RUNNING.value;
        doNothing().when(updated).save(anyString());
        doReturn(updated).when(st).withStatus(ContainerStatus.RUNNING);

        // Build a Spec with non-empty process.args. StartCommand validates
        // that process.args isn't empty before signalling — without this,
        // start refuses with "spec.process.args is missing or empty".
        com.ternbusty.takoyaki.spec.Spec spec = new com.ternbusty.takoyaki.spec.Spec();
        spec.process = new com.ternbusty.takoyaki.spec.Spec.Process();
        spec.process.args = java.util.List.of("/bin/true");

        try (MockedStatic<State> sm = mockStatic(State.class);
             MockedStatic<NotifySocket> nm = mockStatic(NotifySocket.class);
             MockedStatic<com.ternbusty.takoyaki.util.Json> jm =
                     mockStatic(com.ternbusty.takoyaki.util.Json.class)) {
            sm.when(() -> State.load(anyString(), anyString())).thenReturn(st);
            jm.when(() -> com.ternbusty.takoyaki.util.Json.readFile(any(), any()))
                    .thenReturn(spec);
            // pathFor is a pure path builder — let the real one run so the
            // sendStart verification below checks the canonical path.
            nm.when(() -> NotifySocket.pathFor(anyString())).thenCallRealMethod();

            int rc = StartCommand.run(ROOT, "ctr-a");

            assertEquals(0, rc);
            // NotifySocket.sendStart is the actual "go" signal across the
            // unix domain socket — verify it fired with the canonical path.
            nm.verify(() -> NotifySocket.sendStart(eq("/tmp/takoyaki-ctr-a.sock")));
            verify(updated, times(1)).save(eq("/run/takoyaki"));
        }
    }


    @Test
    void startingNonCreatedContainerErrors() {
        State st = spy(createdState());
        st.status = ContainerStatus.RUNNING.value;
        doReturn(st).when(st).refreshStatus();

        try (MockedStatic<State> sm = mockStatic(State.class);
             MockedStatic<NotifySocket> nm = mockStatic(NotifySocket.class)) {
            sm.when(() -> State.load(anyString(), anyString())).thenReturn(st);

            int rc = StartCommand.run(ROOT, "ctr-a");

            assertEquals(1, rc, "OCI: start only valid on a 'created' container");
            // No "go" signal should have been sent.
            nm.verifyNoInteractions();
        }
    }

    @Test
    void stateLoadFailureReturnsError() {
        try (MockedStatic<State> sm = mockStatic(State.class)) {
            sm.when(() -> State.load(anyString(), anyString()))
                    .thenThrow(new IOException("corrupt"));

            int rc = StartCommand.run(ROOT, "ctr-a");

            assertEquals(1, rc);
        }
    }
}
