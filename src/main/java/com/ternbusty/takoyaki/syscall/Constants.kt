package com.ternbusty.takoyaki.syscall

import com.ternbusty.takoyaki.syscall.gen.NativeH

/**
 * Kernel constants, taken from the system headers via the generated
 * [NativeH] (see the jextractSyscall gradle task) rather than hand-written
 * literals. Values therefore match the build machine's headers, and the
 * arch-dependent ones (syscall numbers, O_DIRECTORY) need no manual branch.
 */
object Constants {

    val CLONE_NEWNS: Int = NativeH.CLONE_NEWNS()
    val CLONE_NEWUTS: Int = NativeH.CLONE_NEWUTS()
    val CLONE_NEWIPC: Int = NativeH.CLONE_NEWIPC()
    val CLONE_NEWUSER: Int = NativeH.CLONE_NEWUSER()
    val CLONE_NEWPID: Int = NativeH.CLONE_NEWPID()
    val CLONE_NEWNET: Int = NativeH.CLONE_NEWNET()
    val CLONE_NEWCGROUP: Int = NativeH.CLONE_NEWCGROUP()
    val CLONE_NEWTIME: Int = NativeH.CLONE_NEWTIME()

    val MS_RDONLY: Long = NativeH.MS_RDONLY().toLong()
    val MS_NOSUID: Long = NativeH.MS_NOSUID().toLong()
    val MS_NODEV: Long = NativeH.MS_NODEV().toLong()
    val MS_NOEXEC: Long = NativeH.MS_NOEXEC().toLong()
    val MS_REMOUNT: Long = NativeH.MS_REMOUNT().toLong()
    val MS_BIND: Long = NativeH.MS_BIND().toLong()
    val MS_REC: Long = NativeH.MS_REC().toLong()
    val MS_NOATIME: Long = NativeH.MS_NOATIME().toLong()
    val MS_RELATIME: Long = NativeH.MS_RELATIME().toLong()
    val MS_STRICTATIME: Long = NativeH.MS_STRICTATIME().toLong()
    val MS_NODIRATIME: Long = 2048L   // 0x800, stable across architectures
    val MS_NOSYMFOLLOW: Long = NativeH.MS_NOSYMFOLLOW().toLong()
    val MS_PRIVATE: Long = NativeH.MS_PRIVATE().toLong()
    val MS_SLAVE: Long = NativeH.MS_SLAVE().toLong()
    val MS_SHARED: Long = NativeH.MS_SHARED().toLong()
    val MS_UNBINDABLE: Long = NativeH.MS_UNBINDABLE().toLong()
    val MS_MOVE: Long = 8192L         // 0x2000, stable across architectures

    val MNT_DETACH: Int = NativeH.MNT_DETACH()

    val PR_SET_DUMPABLE: Int = NativeH.PR_SET_DUMPABLE()
    val PR_SET_KEEPCAPS: Int = NativeH.PR_SET_KEEPCAPS()
    val PR_SET_NO_NEW_PRIVS: Int = NativeH.PR_SET_NO_NEW_PRIVS()

    val SIGHUP: Int = NativeH.SIGHUP()
    val SIGINT: Int = NativeH.SIGINT()
    val SIGQUIT: Int = NativeH.SIGQUIT()
    val SIGILL: Int = NativeH.SIGILL()
    val SIGABRT: Int = NativeH.SIGABRT()
    val SIGFPE: Int = NativeH.SIGFPE()
    val SIGKILL: Int = NativeH.SIGKILL()
    val SIGSEGV: Int = NativeH.SIGSEGV()
    val SIGPIPE: Int = NativeH.SIGPIPE()
    val SIGALRM: Int = NativeH.SIGALRM()
    val SIGTERM: Int = NativeH.SIGTERM()
    val SIGUSR1: Int = NativeH.SIGUSR1()
    val SIGUSR2: Int = NativeH.SIGUSR2()
    val SIGCHLD: Int = NativeH.SIGCHLD()
    val SIGCONT: Int = NativeH.SIGCONT()
    val SIGSTOP: Int = NativeH.SIGSTOP()
    val SIGTSTP: Int = NativeH.SIGTSTP()
    val SIGTTIN: Int = NativeH.SIGTTIN()
    val SIGTTOU: Int = NativeH.SIGTTOU()

    val EPERM: Int = NativeH.EPERM()
    val ENOENT: Int = NativeH.ENOENT()
    val ESRCH: Int = NativeH.ESRCH()
    val EINTR: Int = NativeH.EINTR()
    val EEXIST: Int = NativeH.EEXIST()
    val EBUSY: Int = NativeH.EBUSY()
    val EINVAL: Int = NativeH.EINVAL()
    val ENOSYS: Int = NativeH.ENOSYS()

    val AF_UNIX: Int = NativeH.AF_UNIX()
    val AF_INET: Int = NativeH.AF_INET()
    val SOCK_STREAM: Int = NativeH.SOCK_STREAM()
    val SOCK_DGRAM: Int = NativeH.SOCK_DGRAM()

    val F_OK: Int = NativeH.F_OK()
    val O_RDONLY: Int = NativeH.O_RDONLY()
    val O_RDWR: Int = NativeH.O_RDWR()
    val O_CREAT: Int = NativeH.O_CREAT()
    val O_DIRECTORY: Int = NativeH.O_DIRECTORY()

    fun isAarch64(): Boolean {
        val a = System.getProperty("os.arch", "").lowercase()
        return "aarch64" in a || "arm64" in a
    }

    val F_GETFD: Int = NativeH.F_GETFD()
    val F_SETFD: Int = NativeH.F_SETFD()
    val FD_CLOEXEC: Int = NativeH.FD_CLOEXEC()

    val RLIMIT_CPU: Int = NativeH.RLIMIT_CPU()
    val RLIMIT_FSIZE: Int = NativeH.RLIMIT_FSIZE()
    val RLIMIT_DATA: Int = NativeH.RLIMIT_DATA()
    val RLIMIT_STACK: Int = NativeH.RLIMIT_STACK()
    val RLIMIT_CORE: Int = NativeH.RLIMIT_CORE()
    val RLIMIT_RSS: Int = NativeH.RLIMIT_RSS()
    val RLIMIT_NPROC: Int = NativeH.RLIMIT_NPROC()
    val RLIMIT_NOFILE: Int = NativeH.RLIMIT_NOFILE()
    val RLIMIT_MEMLOCK: Int = NativeH.RLIMIT_MEMLOCK()
    val RLIMIT_AS: Int = NativeH.RLIMIT_AS()
    val RLIMIT_LOCKS: Int = NativeH.RLIMIT_LOCKS()
    val RLIMIT_SIGPENDING: Int = NativeH.RLIMIT_SIGPENDING()
    val RLIMIT_MSGQUEUE: Int = NativeH.RLIMIT_MSGQUEUE()
    val RLIMIT_NICE: Int = NativeH.RLIMIT_NICE()
    val RLIMIT_RTPRIO: Int = NativeH.RLIMIT_RTPRIO()
    val RLIMIT_RTTIME: Int = NativeH.RLIMIT_RTTIME()

    val PR_CAPBSET_DROP: Int = NativeH.PR_CAPBSET_DROP()
    val PR_CAP_AMBIENT: Int = NativeH.PR_CAP_AMBIENT()
    val PR_CAP_AMBIENT_RAISE: Int = NativeH.PR_CAP_AMBIENT_RAISE()
    val PR_CAP_AMBIENT_CLEAR_ALL: Int = NativeH.PR_CAP_AMBIENT_CLEAR_ALL()
    val PR_SET_CHILD_SUBREAPER: Int = NativeH.PR_SET_CHILD_SUBREAPER()

    val LINUX_CAPABILITY_VERSION_3: Int = NativeH._LINUX_CAPABILITY_VERSION_3()

    val NR_capset: Long = NativeH.SYS_capset().toLong()
    val NR_close_range: Long = NativeH.SYS_close_range().toLong()
    // glibc ships no pivot_root wrapper (man 2 pivot_root says to use syscall(2)).
    val NR_pivot_root: Long = NativeH.SYS_pivot_root().toLong()
    val NR_chroot: Long = NativeH.SYS_chroot().toLong()
    val NR_keyctl: Long = NativeH.SYS_keyctl().toLong()
    val NR_bpf: Long = NativeH.SYS_bpf().toLong()
    val CLOSE_RANGE_CLOEXEC: Int = NativeH.CLOSE_RANGE_CLOEXEC()

    // ioctl request codes
    val SIOCGIFFLAGS: Long = NativeH.SIOCGIFFLAGS().toLong()
    val SIOCSIFFLAGS: Long = NativeH.SIOCSIFFLAGS().toLong()
    val IFF_UP: Int = NativeH.IFF_UP()
    // TTY ioctl codes (not in jextract headers, stable across Linux architectures)
    val TIOCSCTTY: Long  = 0x540EL
    val TIOCSWINSZ: Long = 0x5414L
    val TIOCGWINSZ: Long = 0x5413L
    // termios ioctl codes (asm-generic, same on x86_64 and aarch64)
    val TCGETS: Long = 0x5401L
    val TCSETS: Long = 0x5402L
    // termios c_oflag bits
    val ONLCR: Int = 0x4

    // mknod / stat mode bits
    val S_IFCHR: Int = NativeH.S_IFCHR()
    val S_IFBLK: Int = NativeH.S_IFBLK()
    val S_IFIFO: Int = NativeH.S_IFIFO()

    val KEYCTL_JOIN_SESSION_KEYRING: Int = NativeH.KEYCTL_JOIN_SESSION_KEYRING()

    // ioprio / scheduler / affinity syscall numbers
    val NR_ioprio_set: Long = NativeH.SYS_ioprio_set().toLong()
    val NR_sched_setattr: Long = NativeH.SYS_sched_setattr().toLong()
    val NR_sched_setaffinity: Long = NativeH.SYS_sched_setaffinity().toLong()

    // ioprio constants (from linux/ioprio.h)
    const val IOPRIO_WHO_PROCESS: Int = 1

    // seccomp(2) (kernel 3.17+, used by patchbpf ENOSYS stub)
    val NR_seccomp: Long = NativeH.SYS_seccomp().toLong()
    // pidfd_open(2) (kernel 5.3+)
    val NR_pidfd_open: Long = NativeH.SYS_pidfd_open().toLong()
    // set_mempolicy(2) for NUMA memory policy
    val NR_set_mempolicy: Long = NativeH.SYS_set_mempolicy().toLong()

    // mount_setattr(2) constants (linux/mount.h, since kernel 5.12)
    // Syscall 442 on both aarch64 and x86_64 (added in 5.12, same ABI number).
    const val NR_mount_setattr: Long = 442L
    const val MOUNT_ATTR_RDONLY: Long       = 0x1L
    const val MOUNT_ATTR_NOSUID: Long       = 0x2L
    const val MOUNT_ATTR_NODEV: Long        = 0x4L
    const val MOUNT_ATTR_NOEXEC: Long       = 0x8L
    const val MOUNT_ATTR_NOATIME: Long      = 0x10L
    const val MOUNT_ATTR_STRICTATIME: Long  = 0x20L
    const val MOUNT_ATTR_NODIRATIME: Long   = 0x80L
    const val MOUNT_ATTR_RELATIME: Long     = 0x0L
    const val MOUNT_ATTR_NOSYMFOLLOW: Long  = 0x200000L
    const val MOUNT_ATTR__ATIME: Long       = 0x70L
    const val AT_RECURSIVE: Int             = 0x8000
}
