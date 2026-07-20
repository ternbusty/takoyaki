package com.ternbusty.takoyaki.syscall;

public final class Constants {
    private Constants() {}

    public static final int CLONE_NEWNS = 0x00020000;
    public static final int CLONE_NEWUTS = 0x04000000;
    public static final int CLONE_NEWIPC = 0x08000000;
    public static final int CLONE_NEWUSER = 0x10000000;
    public static final int CLONE_NEWPID = 0x20000000;
    public static final int CLONE_NEWNET = 0x40000000;
    public static final int CLONE_NEWCGROUP = 0x02000000;
    public static final int CLONE_NEWTIME = 0x00000080;

    public static final long MS_RDONLY = 1L;
    public static final long MS_NOSUID = 2L;
    public static final long MS_NODEV = 4L;
    public static final long MS_NOEXEC = 8L;
    public static final long MS_REMOUNT = 32L;
    public static final long MS_BIND = 4096L;
    public static final long MS_REC = 16384L;
    public static final long MS_NOATIME = 1024L;
    public static final long MS_RELATIME = 1L << 21;
    public static final long MS_STRICTATIME = 1L << 24;
    public static final long MS_NOSYMFOLLOW = 256L;
    public static final long MS_PRIVATE = 1L << 18;
    public static final long MS_SLAVE = 1L << 19;
    public static final long MS_SHARED = 1L << 20;
    public static final long MS_UNBINDABLE = 1L << 17;

    public static final int MNT_DETACH = 2;

    public static final int PR_SET_DUMPABLE = 4;
    public static final int PR_SET_KEEPCAPS = 8;
    public static final int PR_SET_NO_NEW_PRIVS = 38;

    public static final int SIGHUP = 1;
    public static final int SIGINT = 2;
    public static final int SIGQUIT = 3;
    public static final int SIGILL = 4;
    public static final int SIGABRT = 6;
    public static final int SIGFPE = 8;
    public static final int SIGKILL = 9;
    public static final int SIGSEGV = 11;
    public static final int SIGPIPE = 13;
    public static final int SIGALRM = 14;
    public static final int SIGTERM = 15;
    public static final int SIGUSR1 = 10;
    public static final int SIGUSR2 = 12;
    public static final int SIGCHLD = 17;
    public static final int SIGCONT = 18;
    public static final int SIGSTOP = 19;
    public static final int SIGTSTP = 20;
    public static final int SIGTTIN = 21;
    public static final int SIGTTOU = 22;

    public static final int EPERM = 1;
    public static final int ENOENT = 2;
    public static final int ESRCH = 3;
    public static final int EINTR = 4;
    public static final int EEXIST = 17;
    public static final int EBUSY = 16;
    public static final int EINVAL = 22;
    public static final int ENOSYS = 38;

    public static final int AF_UNIX = 1;
    public static final int AF_INET = 2;
    public static final int SOCK_STREAM = 1;
    public static final int SOCK_DGRAM = 2;

    public static final int F_OK = 0;
    public static final int O_RDONLY = 0;
    public static final int O_RDWR = 2;
    public static final int O_CREAT = 0100;
    public static final int O_DIRECTORY = isAarch64() ? 0x4000 : 0x10000;

    public static boolean isAarch64() {
        String a = System.getProperty("os.arch", "").toLowerCase();
        return a.contains("aarch64") || a.contains("arm64");
    }

    public static final int F_GETFD = 1;
    public static final int F_SETFD = 2;
    public static final int FD_CLOEXEC = 1;

    public static final int RLIMIT_CPU = 0;
    public static final int RLIMIT_FSIZE = 1;
    public static final int RLIMIT_DATA = 2;
    public static final int RLIMIT_STACK = 3;
    public static final int RLIMIT_CORE = 4;
    public static final int RLIMIT_RSS = 5;
    public static final int RLIMIT_NPROC = 6;
    public static final int RLIMIT_NOFILE = 7;
    public static final int RLIMIT_MEMLOCK = 8;
    public static final int RLIMIT_AS = 9;
    public static final int RLIMIT_LOCKS = 10;
    public static final int RLIMIT_SIGPENDING = 11;
    public static final int RLIMIT_MSGQUEUE = 12;
    public static final int RLIMIT_NICE = 13;
    public static final int RLIMIT_RTPRIO = 14;
    public static final int RLIMIT_RTTIME = 15;

    public static final int PR_CAPBSET_DROP = 24;
    public static final int PR_CAP_AMBIENT = 47;
    public static final int PR_CAP_AMBIENT_RAISE = 2;
    public static final int PR_CAP_AMBIENT_CLEAR_ALL = 4;
    public static final int PR_SET_CHILD_SUBREAPER = 36;

    public static final int LINUX_CAPABILITY_VERSION_3 = 0x20080522;

    public static final long NR_capset = isAarch64() ? 91L : 126L;
    public static final long NR_close_range = 436L; // same on aarch64 and x86_64
    public static final int CLOSE_RANGE_CLOEXEC = 4;

    // ioctl request codes
    public static final long SIOCGIFFLAGS = 0x8913L;
    public static final long SIOCSIFFLAGS = 0x8914L;
    public static final int IFF_UP = 0x1;

    // mknod / stat mode bits
    public static final int S_IFCHR = 0020000;
    public static final int S_IFBLK = 0060000;
    public static final int S_IFIFO = 0010000;
}
