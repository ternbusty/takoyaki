package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class NamespaceFlagsTest {

    private fun ns(type: String, path: String?): Namespace =
        Namespace(type = type, path = path)

    @Test
    fun nullListReturnsZero() {
        assertEquals(0, NamespaceFlags.fromSpec(null))
    }

    @Test
    fun emptyListReturnsZero() {
        assertEquals(0, NamespaceFlags.fromSpec(listOf()))
    }

    @Test
    fun singleMountNamespace() {
        val flags = NamespaceFlags.fromSpec(listOf(ns("mount", null)))
        assertEquals(Constants.CLONE_NEWNS, flags)
    }

    @Test
    fun allCommonNamespaces() {
        val flags = NamespaceFlags.fromSpec(listOf(
            ns("mount", null),
            ns("pid", null),
            ns("uts", null),
            ns("ipc", null),
            ns("network", null)))
        val expected = Constants.CLONE_NEWNS or Constants.CLONE_NEWPID or
            Constants.CLONE_NEWUTS or Constants.CLONE_NEWIPC or
            Constants.CLONE_NEWNET
        assertEquals(expected, flags)
    }

    @Test
    fun namespaceWithPathIsExcludedFromCloneFlags() {
        // Namespaces with a `path` are joined via setns() in bootstrap.c, NOT
        // created via unshare. They must not appear in the clone flags or we'd
        // try to both join AND create the same namespace.
        val flags = NamespaceFlags.fromSpec(listOf(
            ns("mount", null),
            ns("ipc", "/proc/self/ns/ipc"),
            ns("pid", null)))
        val expected = Constants.CLONE_NEWNS or Constants.CLONE_NEWPID
        assertEquals(expected, flags, "ipc with path should be omitted")
        assertEquals(0, flags and Constants.CLONE_NEWIPC,
            "CLONE_NEWIPC must NOT be set when ipc namespace has a path")
    }

    @Test
    fun emptyPathStringIsTreatedAsNoPath() {
        val flags = NamespaceFlags.fromSpec(listOf(ns("uts", "")))
        assertEquals(Constants.CLONE_NEWUTS, flags,
            "empty-string path is the JSON-default for missing field, treat as no path")
    }

    @Test
    fun unknownNamespaceTypeContributesNothing() {
        val flags = NamespaceFlags.fromSpec(listOf(
            ns("mount", null),
            ns("bogus", null)))
        assertEquals(Constants.CLONE_NEWNS, flags)
    }

    @Test
    fun toFlagCoversEveryDocumentedType() {
        assertEquals(Constants.CLONE_NEWNS, NamespaceFlags.toFlag("mount"))
        assertEquals(Constants.CLONE_NEWNET, NamespaceFlags.toFlag("network"))
        assertEquals(Constants.CLONE_NEWUTS, NamespaceFlags.toFlag("uts"))
        assertEquals(Constants.CLONE_NEWIPC, NamespaceFlags.toFlag("ipc"))
        assertEquals(Constants.CLONE_NEWPID, NamespaceFlags.toFlag("pid"))
        assertEquals(Constants.CLONE_NEWUSER, NamespaceFlags.toFlag("user"))
        assertEquals(Constants.CLONE_NEWCGROUP, NamespaceFlags.toFlag("cgroup"))
        assertEquals(Constants.CLONE_NEWTIME, NamespaceFlags.toFlag("time"))
        assertEquals(0, NamespaceFlags.toFlag("bogus"))
        assertEquals(0, NamespaceFlags.toFlag(null))
    }
}
