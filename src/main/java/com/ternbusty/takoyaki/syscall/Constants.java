package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.syscall.gen.NativeH;

/**
 * Kernel constants, taken from the system headers via the generated
 * {@link NativeH} (see the jextractSyscall gradle task) rather than hand-written
 * literals. Values therefore match the build machine's headers, and the
 * arch-dependent ones (syscall numbers, O_DIRECTORY) need no manual branch.
 */
public final class Constants {
    private Constants() {}


    public static final int CLONE_NEWNS = NativeH.CLONE_NEWNS();
    public static final int CLONE_NEWUTS = NativeH.CLONE_NEWUTS();
    public static final int CLONE_NEWIPC = NativeH.CLONE_NEWIPC();
    public static final int CLONE_NEWUSER = NativeH.CLONE_NEWUSER();
    public static final int CLONE_NEWPID = NativeH.CLONE_NEWPID();
    public static final int CLONE_NEWNET = NativeH.CLONE_NEWNET();
    public static final int CLONE_NEWCGROUP = NativeH.CLONE_NEWCGROUP();
    public static final int CLONE_NEWTIME = NativeH.CLONE_NEWTIME();

    public static final long MS_RDONLY = NativeH.MS_RDONLY();
    public static final long MS_NOSUID = NativeH.MS_NOSUID();
    public static final long MS_NODEV = NativeH.MS_NODEV();
    public static final long MS_NOEXEC = NativeH.MS_NOEXEC();
    public static final long MS_REMOUNT = NativeH.MS_REMOUNT();
    public static final long MS_BIND = NativeH.MS_BIND();
    public static final long MS_REC = NativeH.MS_REC();
    public static final long MS_NOATIME = NativeH.MS_NOATIME();
    public static final long MS_RELATIME = NativeH.MS_RELATIME();
    public static final long MS_STRICTATIME = NativeH.MS_STRICTATIME();
    public static final long MS_NODIRATIME = 2048L;   // 0x800, stable across architectures
    public static final long MS_NOSYMFOLLOW = NativeH.MS_NOSYMFOLLOW();
    public static final long MS_PRIVATE = NativeH.MS_PRIVATE();
    public static final long MS_SLAVE = NativeH.MS_SLAVE();
    public static final long MS_SHARED = NativeH.MS_SHARED();
    public static final long MS_UNBINDABLE = NativeH.MS_UNBINDABLE();
    public static final long MS_MOVE = 8192L;         // 0x2000, stable across architectures

    public static final int MNT_DETACH = NativeH.MNT_DETACH();

    public static final int PR_SET_DUMPABLE = NativeH.PR_SET_DUMPABLE();
    public static final int PR_SET_KEEPCAPS = NativeH.PR_SET_KEEPCAPS();
    public static final int PR_SET_NO_NEW_PRIVS = NativeH.PR_SET_NO_NEW_PRIVS();

    public static final int SIGHUP = NativeH.SIGHUP();
    public static final int SIGINT = NativeH.SIGINT();
    public static final int SIGQUIT = NativeH.SIGQUIT();
    public static final int SIGILL = NativeH.SIGILL();
    public static final int SIGABRT = NativeH.SIGABRT();
    public static final int SIGFPE = NativeH.SIGFPE();
    public static final int SIGKILL = NativeH.SIGKILL();
    public static final int SIGSEGV = NativeH.SIGSEGV();
    public static final int SIGPIPE = NativeH.SIGPIPE();
    public static final int SIGALRM = NativeH.SIGALRM();
    public static final int SIGTERM = NativeH.SIGTERM();
    public static final int SIGUSR1 = NativeH.SIGUSR1();
    public static final int SIGUSR2 = NativeH.SIGUSR2();
    public static final int SIGCHLD = NativeH.SIGCHLD();
    public static final int SIGCONT = NativeH.SIGCONT();
    public static final int SIGSTOP = NativeH.SIGSTOP();
    public static final int SIGTSTP = NativeH.SIGTSTP();
    public static final int SIGTTIN = NativeH.SIGTTIN();
    public static final int SIGTTOU = NativeH.SIGTTOU();

    public static final int EPERM = NativeH.EPERM();
    public static final int ENOENT = NativeH.ENOENT();
    public static final int ESRCH = NativeH.ESRCH();
    public static final int EINTR = NativeH.EINTR();
    public static final int EEXIST = NativeH.EEXIST();
    public static final int EBUSY = NativeH.EBUSY();
    public static final int EINVAL = NativeH.EINVAL();
    public static final int ENOSYS = NativeH.ENOSYS();

    public static final int AF_UNIX = NativeH.AF_UNIX();
    public static final int AF_INET = NativeH.AF_INET();
    public static final int SOCK_STREAM = NativeH.SOCK_STREAM();
    public static final int SOCK_DGRAM = NativeH.SOCK_DGRAM();

    public static final int F_OK = NativeH.F_OK();
    public static final int O_RDONLY = NativeH.O_RDONLY();
    public static final int O_RDWR = NativeH.O_RDWR();
    public static final int O_CREAT = NativeH.O_CREAT();
    public static final int O_DIRECTORY = NativeH.O_DIRECTORY();

    public static boolean isAarch64() {
        String a = System.getProperty("os.arch", "").toLowerCase();
        return a.contains("aarch64") || a.contains("arm64");
    }

    public static final int F_GETFD = NativeH.F_GETFD();
    public static final int F_SETFD = NativeH.F_SETFD();
    public static final int FD_CLOEXEC = NativeH.FD_CLOEXEC();

    public static final int RLIMIT_CPU = NativeH.RLIMIT_CPU();
    public static final int RLIMIT_FSIZE = NativeH.RLIMIT_FSIZE();
    public static final int RLIMIT_DATA = NativeH.RLIMIT_DATA();
    public static final int RLIMIT_STACK = NativeH.RLIMIT_STACK();
    public static final int RLIMIT_CORE = NativeH.RLIMIT_CORE();
    public static final int RLIMIT_RSS = NativeH.RLIMIT_RSS();
    public static final int RLIMIT_NPROC = NativeH.RLIMIT_NPROC();
    public static final int RLIMIT_NOFILE = NativeH.RLIMIT_NOFILE();
    public static final int RLIMIT_MEMLOCK = NativeH.RLIMIT_MEMLOCK();
    public static final int RLIMIT_AS = NativeH.RLIMIT_AS();
    public static final int RLIMIT_LOCKS = NativeH.RLIMIT_LOCKS();
    public static final int RLIMIT_SIGPENDING = NativeH.RLIMIT_SIGPENDING();
    public static final int RLIMIT_MSGQUEUE = NativeH.RLIMIT_MSGQUEUE();
    public static final int RLIMIT_NICE = NativeH.RLIMIT_NICE();
    public static final int RLIMIT_RTPRIO = NativeH.RLIMIT_RTPRIO();
    public static final int RLIMIT_RTTIME = NativeH.RLIMIT_RTTIME();

    public static final int PR_CAPBSET_DROP = NativeH.PR_CAPBSET_DROP();
    public static final int PR_CAP_AMBIENT = NativeH.PR_CAP_AMBIENT();
    public static final int PR_CAP_AMBIENT_RAISE = NativeH.PR_CAP_AMBIENT_RAISE();
    public static final int PR_CAP_AMBIENT_CLEAR_ALL = NativeH.PR_CAP_AMBIENT_CLEAR_ALL();
    public static final int PR_SET_CHILD_SUBREAPER = NativeH.PR_SET_CHILD_SUBREAPER();

    public static final int LINUX_CAPABILITY_VERSION_3 = NativeH._LINUX_CAPABILITY_VERSION_3();

    public static final long NR_capset = NativeH.SYS_capset();
    public static final long NR_close_range = NativeH.SYS_close_range();
    // glibc ships no pivot_root wrapper (man 2 pivot_root says to use syscall(2)).
    public static final long NR_pivot_root = NativeH.SYS_pivot_root();
    public static final long NR_chroot = NativeH.SYS_chroot();
    public static final long NR_keyctl = NativeH.SYS_keyctl();
    public static final long NR_bpf = NativeH.SYS_bpf();
    public static final int CLOSE_RANGE_CLOEXEC = NativeH.CLOSE_RANGE_CLOEXEC();

    // ioctl request codes
    public static final long SIOCGIFFLAGS = NativeH.SIOCGIFFLAGS();
    public static final long SIOCSIFFLAGS = NativeH.SIOCSIFFLAGS();
    public static final int IFF_UP = NativeH.IFF_UP();
    // TTY ioctl codes (not in jextract headers, stable across Linux architectures)
    public static final long TIOCSCTTY  = 0x540EL;
    public static final long TIOCSWINSZ = 0x5414L;
    public static final long TIOCGWINSZ = 0x5413L;
    // termios ioctl codes (asm-generic, same on x86_64 and aarch64)
    public static final long TCGETS = 0x5401L;
    public static final long TCSETS = 0x5402L;
    // termios c_oflag bits
    public static final int ONLCR = 0x4;

    // mknod / stat mode bits
    public static final int S_IFCHR = NativeH.S_IFCHR();
    public static final int S_IFBLK = NativeH.S_IFBLK();
    public static final int S_IFIFO = NativeH.S_IFIFO();

    public static final int KEYCTL_JOIN_SESSION_KEYRING = NativeH.KEYCTL_JOIN_SESSION_KEYRING();

    // ioprio / scheduler / affinity syscall numbers
    public static final long NR_ioprio_set = NativeH.SYS_ioprio_set();
    public static final long NR_sched_setattr = NativeH.SYS_sched_setattr();
    public static final long NR_sched_setaffinity = NativeH.SYS_sched_setaffinity();

    // ioprio constants (from linux/ioprio.h)
    public static final int IOPRIO_WHO_PROCESS = 1;

    // seccomp(2) (kernel 3.17+, used by patchbpf ENOSYS stub)
    public static final long NR_seccomp = NativeH.SYS_seccomp();
    // pidfd_open(2) (kernel 5.3+)
    public static final long NR_pidfd_open = NativeH.SYS_pidfd_open();
    // set_mempolicy(2) for NUMA memory policy
    public static final long NR_set_mempolicy = NativeH.SYS_set_mempolicy();

    // mount_setattr(2) constants (linux/mount.h, since kernel 5.12)
    // Syscall 442 on both aarch64 and x86_64 (added in 5.12, same ABI number).
    public static final long NR_mount_setattr = 442L;
    public static final long MOUNT_ATTR_RDONLY       = 0x1L;
    public static final long MOUNT_ATTR_NOSUID       = 0x2L;
    public static final long MOUNT_ATTR_NODEV        = 0x4L;
    public static final long MOUNT_ATTR_NOEXEC       = 0x8L;
    public static final long MOUNT_ATTR_NOATIME      = 0x10L;
    public static final long MOUNT_ATTR_STRICTATIME  = 0x20L;
    public static final long MOUNT_ATTR_NODIRATIME   = 0x80L;
    public static final long MOUNT_ATTR_RELATIME     = 0x0L;
    public static final long MOUNT_ATTR_NOSYMFOLLOW  = 0x200000L;
    public static final long MOUNT_ATTR__ATIME       = 0x70L;
    public static final int  AT_RECURSIVE            = 0x8000;
}
