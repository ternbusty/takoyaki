package com.ternbusty.takoyaki.command

import com.ternbusty.takoyaki.util.JsonCodec
/**
 * Output the enabled features of the runtime as JSON. This is used by
 * the runc integration tests to discover supported seccomp flags and
 * other capabilities.
 */
object FeaturesCommand {

    fun run(): Int {
        val f = linkedMapOf<String, Any>(
            "ociVersionMin" to "1.0.0",
            "ociVersionMax" to "1.0.2",
            "hooks" to listOf(
                "prestart", "createRuntime", "createContainer",
                "startContainer", "poststart", "poststop"
            ),
            "mountOptions" to mountOptions(),
        )

        val cgroup = linkedMapOf<String, Any>(
            "v1" to false,
            "v2" to true,
            "systemd" to false,
            "systemdUser" to false,
        )

        val seccomp = linkedMapOf<String, Any>(
            "enabled" to true,
            "actions" to listOf(
                "SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL",
                "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD",
                "SCMP_ACT_LOG", "SCMP_ACT_TRACE", "SCMP_ACT_TRAP"
            ),
            "operators" to listOf(
                "SCMP_CMP_EQ", "SCMP_CMP_GE", "SCMP_CMP_GT",
                "SCMP_CMP_LE", "SCMP_CMP_LT", "SCMP_CMP_MASKED_EQ", "SCMP_CMP_NE"
            ),
            "archs" to seccompArchs(),
            "knownFlags" to listOf(
                "SECCOMP_FILTER_FLAG_TSYNC",
                "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
                "SECCOMP_FILTER_FLAG_LOG",
                "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"
            ),
            "supportedFlags" to listOf(
                "SECCOMP_FILTER_FLAG_TSYNC",
                "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
                "SECCOMP_FILTER_FLAG_LOG",
                "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"
            ),
        )

        val apparmor = linkedMapOf<String, Any>(
            "enabled" to true,
        )

        val linux = linkedMapOf<String, Any>(
            "namespaces" to listOf(
                "cgroup", "ipc", "mount", "network", "pid", "time", "user", "uts"
            ),
            "capabilities" to capabilities(),
            "cgroup" to cgroup,
            "seccomp" to seccomp,
            "apparmor" to apparmor,
        )

        f["linux"] = linux
        println(JsonCodec.encodePretty(JsonCodec.toJsonElement(f)))
        return 0
    }

    private fun mountOptions(): List<String> = listOf(
        "async", "atime", "bind", "defaults", "dev", "diratime",
        "dirsync", "exec", "iversion", "lazytime", "loud", "mand",
        "noatime", "nodev", "nodiratime", "noexec", "noiversion",
        "nolazytime", "nomand", "norelatime", "nostrictatime",
        "nosuid", "nosymfollow", "private", "ratime", "rbind",
        "rdev", "rdiratime", "relatime", "remount", "rexec",
        "rnoatime", "rnodev", "rnodiratime", "rnoexec",
        "rnorelatime", "rnostrictatime", "rnosuid", "rnosymfollow",
        "ro", "rprivate", "rrelatime", "rro", "rrw", "rshared",
        "rslave", "rstrictatime", "rsuid", "rsymfollow",
        "runbindable", "rw", "shared", "silent", "slave",
        "strictatime", "suid", "symfollow", "sync", "tmpcopyup",
        "unbindable"
    )

    private fun capabilities(): List<String> = listOf(
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID",
        "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN",
        "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
        "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
        "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
        "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE"
    )

    private fun seccompArchs(): List<String> = listOf(
        "SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM",
        "SCMP_ARCH_MIPS", "SCMP_ARCH_MIPS64", "SCMP_ARCH_MIPS64N32",
        "SCMP_ARCH_MIPSEL", "SCMP_ARCH_MIPSEL64", "SCMP_ARCH_MIPSEL64N32",
        "SCMP_ARCH_PPC", "SCMP_ARCH_PPC64", "SCMP_ARCH_PPC64LE",
        "SCMP_ARCH_RISCV64",
        "SCMP_ARCH_S390", "SCMP_ARCH_S390X",
        "SCMP_ARCH_X32", "SCMP_ARCH_X86", "SCMP_ARCH_X86_64"
    )
}
