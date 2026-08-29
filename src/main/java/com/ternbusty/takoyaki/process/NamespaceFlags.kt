package com.ternbusty.takoyaki.process

import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants

object NamespaceFlags {

    fun fromSpec(namespaces: List<Namespace>?): Int {
        if (namespaces == null) return 0
        var flags = 0
        for (ns in namespaces) {
            // Namespaces with an explicit `path` field are joined via setns()
            // by bootstrap.c, not created via unshare — leave them out of the
            // clone flags.
            if (!ns.path.isNullOrEmpty()) continue
            flags = flags or toFlag(ns.type)
        }
        return flags
    }

    fun toFlag(type: String?): Int = when (type) {
        "mount" -> Constants.CLONE_NEWNS
        "network" -> Constants.CLONE_NEWNET
        "uts" -> Constants.CLONE_NEWUTS
        "ipc" -> Constants.CLONE_NEWIPC
        "pid" -> Constants.CLONE_NEWPID
        "user" -> Constants.CLONE_NEWUSER
        "cgroup" -> Constants.CLONE_NEWCGROUP
        "time" -> Constants.CLONE_NEWTIME
        else -> 0
    }
}
