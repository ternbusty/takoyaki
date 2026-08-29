package com.ternbusty.takoyaki.state

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class ContainerStatusTest {

    @Test
    fun fromStringMatchesOciSpec() {
        assertEquals(ContainerStatus.CREATING, ContainerStatus.fromString("creating"))
        assertEquals(ContainerStatus.CREATED, ContainerStatus.fromString("created"))
        assertEquals(ContainerStatus.RUNNING, ContainerStatus.fromString("running"))
        assertEquals(ContainerStatus.STOPPED, ContainerStatus.fromString("stopped"))
    }

    @Test
    fun fromStringUnknownThrows() {
        // Unknown / null inputs are programmer errors at the call site (state
        // file corruption or a typo), so fail fast rather than silently
        // bucketing them into one of the four real statuses.
        assertThrows(IllegalArgumentException::class.java) {
            ContainerStatus.fromString("garbage")
        }
        assertThrows(NullPointerException::class.java) {
            @Suppress("CAST_NEVER_SUCCEEDS")
            ContainerStatus.fromString(null as String)
        }
    }

    @Test
    fun canStartOnlyFromCreated() {
        // OCI runtime spec: `start` is only valid on a `created` container.
        assertTrue(ContainerStatus.CREATED.canStart())
        assertFalse(ContainerStatus.CREATING.canStart())
        assertFalse(ContainerStatus.RUNNING.canStart())
        assertFalse(ContainerStatus.STOPPED.canStart())
    }

    @Test
    fun canKillRequiresCreatedOrRunning() {
        // OCI: "if the container is neither created nor running, kill MUST error".
        assertTrue(ContainerStatus.CREATED.canKill())
        assertTrue(ContainerStatus.RUNNING.canKill())
        assertFalse(ContainerStatus.CREATING.canKill())
        assertFalse(ContainerStatus.STOPPED.canKill())
    }

    @Test
    fun canDeleteOnlyFromStopped() {
        // Without --force, delete is rejected unless the container has stopped.
        assertTrue(ContainerStatus.STOPPED.canDelete())
        assertFalse(ContainerStatus.CREATING.canDelete())
        assertFalse(ContainerStatus.CREATED.canDelete())
        assertFalse(ContainerStatus.RUNNING.canDelete())
    }

    @Test
    fun valueIsTheOciSpecString() {
        // The state JSON we hand to runtime-tools / hooks must use the spec's
        // exact lowercase status strings.
        assertEquals("creating", ContainerStatus.CREATING.value)
        assertEquals("created", ContainerStatus.CREATED.value)
        assertEquals("running", ContainerStatus.RUNNING.value)
        assertEquals("stopped", ContainerStatus.STOPPED.value)
    }
}
