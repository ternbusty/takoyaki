package com.ternbusty.takoyaki.syscall;

import com.ternbusty.takoyaki.syscall.hdr.Consts;

/**
 * Kernel constants, taken from the system headers via the generated
 * {@link Consts} (see the jextractConsts gradle task) rather than hand-written
 * literals. Values therefore match the build machine's headers, and the
 * arch-dependent ones (syscall numbers, O_DIRECTORY) need no manual branch.
 */
public final class Constants {
    private Constants() {}

    public static final int CLONE_NEWNS = Consts.CLONE_NEWNS();
    public static final int CLONE_NEWUTS = Consts.CLONE_NEWUTS();
    public static final int CLONE_NEWIPC = Consts.CLONE_NEWIPC();
    public static final int CLONE_NEWUSER = Consts.CLONE_NEWUSER();
    public static final int CLONE_NEWPID = Consts.CLONE_NEWPID();
    public static final int CLONE_NEWNET = Consts.CLONE_NEWNET();
    public static final int CLONE_NEWCGROUP = Consts.CLONE_NEWCGROUP();
    public static final int CLONE_NEWTIME = Consts.CLONE_NEWTIME();

    public static final long MS_RDONLY = Consts.MS_RDONLY();
    public static final long MS_NOSUID = Consts.MS_NOSUID();
    public static final long MS_NODEV = Consts.MS_NODEV();
    public static final long MS_NOEXEC = Consts.MS_NOEXEC();
    public static final long MS_REMOUNT = Consts.MS_REMOUNT();
    public static final long MS_BIND = Consts.MS_BIND();
    public static final long MS_REC = Consts.MS_REC();
    public static final long MS_NOATIME = Consts.MS_NOATIME();
    public static final long MS_RELATIME = Consts.MS_RELATIME();
    public static final long MS_STRICTATIME = Consts.MS_STRICTATIME();
    public static final long MS_NOSYMFOLLOW = Consts.MS_NOSYMFOLLOW();
    public static final long MS_PRIVATE = Consts.MS_PRIVATE();
    public static final long MS_SLAVE = Consts.MS_SLAVE();
    public static final long MS_SHARED = Consts.MS_SHARED();
    public static final long MS_UNBINDABLE = Consts.MS_UNBINDABLE();

    public static final int MNT_DETACH = Consts.MNT_DETACH();

    public static final int PR_SET_DUMPABLE = Consts.PR_SET_DUMPABLE();
    public static final int PR_SET_KEEPCAPS = Consts.PR_SET_KEEPCAPS();
    public static final int PR_SET_NO_NEW_PRIVS = Consts.PR_SET_NO_NEW_PRIVS();

    public static final int SIGHUP = Consts.SIGHUP();
    public static final int SIGINT = Consts.SIGINT();
    public static final int SIGQUIT = Consts.SIGQUIT();
    public static final int SIGILL = Consts.SIGILL();
    public static final int SIGABRT = Consts.SIGABRT();
    public static final int SIGFPE = Consts.SIGFPE();
    public static final int SIGKILL = Consts.SIGKILL();
    public static final int SIGSEGV = Consts.SIGSEGV();
    public static final int SIGPIPE = Consts.SIGPIPE();
    public static final int SIGALRM = Consts.SIGALRM();
    public static final int SIGTERM = Consts.SIGTERM();
    public static final int SIGUSR1 = Consts.SIGUSR1();
    public static final int SIGUSR2 = Consts.SIGUSR2();
    public static final int SIGCHLD = Consts.SIGCHLD();
    public static final int SIGCONT = Consts.SIGCONT();
    public static final int SIGSTOP = Consts.SIGSTOP();
    public static final int SIGTSTP = Consts.SIGTSTP();
    public static final int SIGTTIN = Consts.SIGTTIN();
    public static final int SIGTTOU = Consts.SIGTTOU();

    public static final int EPERM = Consts.EPERM();
    public static final int ENOENT = Consts.ENOENT();
    public static final int ESRCH = Consts.ESRCH();
    public static final int EINTR = Consts.EINTR();
    public static final int EEXIST = Consts.EEXIST();
    public static final int EBUSY = Consts.EBUSY();
    public static final int EINVAL = Consts.EINVAL();
    public static final int ENOSYS = Consts.ENOSYS();

    public static final int AF_UNIX = Consts.AF_UNIX();
    public static final int AF_INET = Consts.AF_INET();
    public static final int SOCK_STREAM = Consts.SOCK_STREAM();
    public static final int SOCK_DGRAM = Consts.SOCK_DGRAM();

    public static final int F_OK = Consts.F_OK();
    public static final int O_RDONLY = Consts.O_RDONLY();
    public static final int O_RDWR = Consts.O_RDWR();
    public static final int O_CREAT = Consts.O_CREAT();
    public static final int O_DIRECTORY = Consts.O_DIRECTORY();

    public static boolean isAarch64() {
        String a = System.getProperty("os.arch", "").toLowerCase();
        return a.contains("aarch64") || a.contains("arm64");
    }

    public static final int F_GETFD = Consts.F_GETFD();
    public static final int F_SETFD = Consts.F_SETFD();
    public static final int FD_CLOEXEC = Consts.FD_CLOEXEC();

    public static final int RLIMIT_CPU = Consts.RLIMIT_CPU();
    public static final int RLIMIT_FSIZE = Consts.RLIMIT_FSIZE();
    public static final int RLIMIT_DATA = Consts.RLIMIT_DATA();
    public static final int RLIMIT_STACK = Consts.RLIMIT_STACK();
    public static final int RLIMIT_CORE = Consts.RLIMIT_CORE();
    public static final int RLIMIT_RSS = Consts.RLIMIT_RSS();
    public static final int RLIMIT_NPROC = Consts.RLIMIT_NPROC();
    public static final int RLIMIT_NOFILE = Consts.RLIMIT_NOFILE();
    public static final int RLIMIT_MEMLOCK = Consts.RLIMIT_MEMLOCK();
    public static final int RLIMIT_AS = Consts.RLIMIT_AS();
    public static final int RLIMIT_LOCKS = Consts.RLIMIT_LOCKS();
    public static final int RLIMIT_SIGPENDING = Consts.RLIMIT_SIGPENDING();
    public static final int RLIMIT_MSGQUEUE = Consts.RLIMIT_MSGQUEUE();
    public static final int RLIMIT_NICE = Consts.RLIMIT_NICE();
    public static final int RLIMIT_RTPRIO = Consts.RLIMIT_RTPRIO();
    public static final int RLIMIT_RTTIME = Consts.RLIMIT_RTTIME();

    public static final int PR_CAPBSET_DROP = Consts.PR_CAPBSET_DROP();
    public static final int PR_CAP_AMBIENT = Consts.PR_CAP_AMBIENT();
    public static final int PR_CAP_AMBIENT_RAISE = Consts.PR_CAP_AMBIENT_RAISE();
    public static final int PR_CAP_AMBIENT_CLEAR_ALL = Consts.PR_CAP_AMBIENT_CLEAR_ALL();
    public static final int PR_SET_CHILD_SUBREAPER = Consts.PR_SET_CHILD_SUBREAPER();

    public static final int LINUX_CAPABILITY_VERSION_3 = Consts._LINUX_CAPABILITY_VERSION_3();

    public static final long NR_capset = Consts.SYS_capset();
    public static final long NR_close_range = Consts.SYS_close_range();
    // glibc ships no pivot_root wrapper (man 2 pivot_root says to use syscall(2)).
    public static final long NR_pivot_root = Consts.SYS_pivot_root();
    public static final long NR_keyctl = Consts.SYS_keyctl();
    public static final long NR_bpf = Consts.SYS_bpf();
    public static final int CLOSE_RANGE_CLOEXEC = Consts.CLOSE_RANGE_CLOEXEC();

    // ioctl request codes
    public static final long SIOCGIFFLAGS = Consts.SIOCGIFFLAGS();
    public static final long SIOCSIFFLAGS = Consts.SIOCSIFFLAGS();
    public static final int IFF_UP = Consts.IFF_UP();

    // mknod / stat mode bits
    public static final int S_IFCHR = Consts.S_IFCHR();
    public static final int S_IFBLK = Consts.S_IFBLK();
    public static final int S_IFIFO = Consts.S_IFIFO();

    public static final int KEYCTL_JOIN_SESSION_KEYRING = Consts.KEYCTL_JOIN_SESSION_KEYRING();
}
