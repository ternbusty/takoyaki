#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>

/* Earliest possible startup timestamp. Set in the constructor below.
 * Java side reads this via takoyaki_get_t0_ns() to compute "ms from
 * constructor entry to Java main()". */
static struct timespec t0_constructor;
static int t0_set = 0;

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#ifndef CLONE_PARENT
#define CLONE_PARENT 0x00008000
#endif

#define ENV_IS_BOOTSTRAP "_TAKOYAKI_IS_BOOTSTRAP"
#define ENV_SYNCPIPE "_TAKOYAKI_SYNCPIPE"
#define ENV_CLONE_FLAGS "_TAKOYAKI_CLONE_FLAGS"
#define ENV_DEBUG "_TAKOYAKI_BOOTSTRAP_DEBUG"

enum sync_t {
    SYNC_USERMAP_PLS = 0x40,
    SYNC_USERMAP_ACK = 0x41,
    SYNC_CGROUP_ACK  = 0x42,
    SYNC_GRANDCHILD = 0x44,
    SYNC_CHILD_FINISH = 0x45,
};

static int debug_enabled = 0;

#define DBG(fmt, ...) do { if (debug_enabled) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

static void log_cpu_affinity(void) {
    if (!debug_enabled) return;
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    if (sched_getaffinity(0, sizeof(cpus), &cpus) < 0) {
        DBG("sched_getaffinity: %s\n", strerror(errno));
        return;
    }
    size_t i, mask = 0;
    for (i = 0; i < sizeof(mask) * 8; i++) {
        if (CPU_ISSET(i, &cpus))
            mask |= (size_t)1 << i;
    }
    DBG("nsexec: affinity: 0x%zx\n", mask);
}

static int getenv_int(const char *name) {
    char *val = getenv(name);
    if (!val) return -1;
    return atoi(val);
}

static unsigned int parse_hex(const char *str) {
    unsigned int result = 0;
    if (!str) return 0;
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) str += 2;
    while (*str) {
        char c = *str;
        unsigned int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else break;
        result = (result << 4) | digit;
        str++;
    }
    return result;
}

static unsigned int getenv_uint_hex(const char *name) {
    char *val = getenv(name);
    if (!val) return 0;
    return parse_hex(val);
}

/* clone3 args struct (subset that we use). The kernel struct is versioned by length. */
struct takoyaki_clone_args {
    unsigned long flags;
    unsigned long pidfd;
    unsigned long child_tid;
    unsigned long parent_tid;
    unsigned long exit_signal;
    unsigned long stack;
    unsigned long stack_size;
    unsigned long tls;
    unsigned long set_tid;
    unsigned long set_tid_size;
    unsigned long cgroup;
};

#ifndef __NR_clone3
# if defined(__aarch64__)
#  define __NR_clone3 435
# else
#  define __NR_clone3 435
# endif
#endif

/* Try clone3 first (provides CLONE_PIDFD and a tidy interface) and fall back to clone
 * if the kernel is too old. The returned pidfd is currently unused but the migration
 * to clone3 is cheap and brings us in line with modern runtimes. */
static pid_t clone_parent(void) {
    struct takoyaki_clone_args ca = {0};
    ca.flags = CLONE_PARENT;
    ca.exit_signal = SIGCHLD;
    long rc = syscall(__NR_clone3, &ca, sizeof(ca));
    if (rc >= 0) return (pid_t) rc;
    if (errno != ENOSYS && errno != EINVAL) {
        fprintf(stderr, "[clone_parent] clone3 failed: %s, falling back to clone\n",
                strerror(errno));
    }
    pid_t pid = syscall(SYS_clone, SIGCHLD | CLONE_PARENT, NULL, NULL, NULL, NULL);
    if (pid < 0) {
        fprintf(stderr, "[clone_parent] clone failed: %s\n", strerror(errno));
    }
    return pid;
}

/* exec path, mirroring the create path's stage machinery (and runc's nsexec):
 * ExecCommand re-execs /proc/self/exe __exec__ with _TAKOYAKI_EXEC_PAYLOAD_FD
 * (a socketpair to the CLI) and the container namespace fds in
 * _TAKOYAKI_EXEC_NS_FDS (format type:fd,type:fd,... in the order they must be
 * applied: user first, cgroup before mnt, mnt last).
 *
 * Everything namespace-related happens right here, before SubstrateVM spawns
 * its runtime helper threads:
 *
 *   1. setns into every fd. Must be pre-Java: setns(mnt/user) rejects
 *      multi-threaded callers with EINVAL. nstype 0 accepts whatever the
 *      fd is.
 *   2. clone_parent() the workload process. The clone is what makes Java
 *      startup work at all inside the container: the child is BORN in the
 *      container pid ns (setns(pid) only affects children), so the container
 *      /proc that isolate creation reads (/proc/self/maps) has an entry for
 *      it, and pid_ns_for_children matches its active ns so CLONE_THREAD —
 *      i.e. the runtime threads — is permitted again. CLONE_PARENT makes the
 *      workload a direct child of the CLI, which can then waitpid it for the
 *      exit code (or simply exit for a detached exec, orphaning the workload
 *      to the caller's subreaper — how containerd's shim reaps it).
 *   3. The intermediate reports the workload's pid — as seen from the host
 *      pid ns, since this process never left it — over the payload socket
 *      (the CLI needs it for cgroup.procs and --pid-file) and exits.
 *
 * The child returns into the normal startup path: SubstrateVM boots inside
 * the container namespaces and Main dispatches to ExecProcess, which applies
 * the process restrictions and execve's the user command in place.
 *
 * Failure is fatal: silently running the exec'd command half-outside the
 * container would defeat the restrictions the exec path exists to apply. */
/* Walk the _TAKOYAKI_EXEC_NS_FDS list and setns each entry, restricted to
 * either the mnt entry (want_mnt=1) or everything else (want_mnt=0). */
static void exec_setns_pass(const char *env, int want_mnt) {
    char *copy = strdup(env);
    if (!copy) {
        fprintf(stderr, "[exec-setns] strdup failed\n");
        exit(1);
    }
    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        char *colon = strchr(token, ':');
        if (colon) {
            *colon = '\0';
            int fd = atoi(colon + 1);
            int is_mnt = strcmp(token, "mnt") == 0;
            if (is_mnt == want_mnt) {
                if (setns(fd, 0) < 0) {
                    fprintf(stderr, "[exec-setns] setns(%s, fd=%d) failed: %s\n",
                            token, fd, strerror(errno));
                    exit(1);
                }
                close(fd);
                /* After joining a user namespace, become root in it so
                 * the kernel restores our effective capabilities. Without
                 * this, subsequent setns(mnt) or mount operations fail
                 * with EPERM. */
                if (strcmp(token, "user") == 0) {
                    if (setuid(0) < 0) {
                        fprintf(stderr, "[exec-setns] setuid(0) after user setns failed: %s\n",
                                strerror(errno));
                        exit(1);
                    }
                    if (setgid(0) < 0) {
                        fprintf(stderr, "[exec-setns] setgid(0) after user setns failed: %s\n",
                                strerror(errno));
                        exit(1);
                    }
                    DBG("[exec-setns] now root in joined user namespace\n");
                }
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
}

static void exec_bootstrap(void) {
    char *sync_env = getenv("_TAKOYAKI_EXEC_PAYLOAD_FD");
    if (!sync_env) return;
    int sync_fd = atoi(sync_env);

    /* Enable debug output for exec path (mirrors create path's ENV_DEBUG). */
    debug_enabled = getenv("_TAKOYAKI_EXEC_DEBUG") != NULL;

    /* Redirect stderr to the log file so that DBG() messages from the exec
     * bootstrap go to the same log file the CLI specified via --log. */
    {
        const char *log_file = getenv("_TAKOYAKI_LOG_FILE");
        if (log_file) {
            int log_fd = open(log_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (log_fd >= 0) {
                dup2(log_fd, STDERR_FILENO);
                close(log_fd);
            }
        }
    }

    /* Apply initial CPU affinity before any namespace operations.
     * This sets the affinity on our thread; the child inherits it via clone. */
    {
        const char *cpu_initial = getenv("_TAKOYAKI_EXEC_CPU_INITIAL");
        if (cpu_initial) {
            unsigned int mask_val = parse_hex(cpu_initial);
            if (mask_val) {
                cpu_set_t cpus;
                CPU_ZERO(&cpus);
                for (unsigned int i = 0; i < sizeof(mask_val) * 8; i++) {
                    if (mask_val & (1u << i))
                        CPU_SET(i, &cpus);
                }
                if (sched_setaffinity(0, sizeof(cpus), &cpus) < 0) {
                    DBG("sched_setaffinity(initial 0x%x): %s\n", mask_val, strerror(errno));
                }
            }
        }
    }

    DBG("nsexec container setup\n");
    log_cpu_affinity();

    char *ns_env = getenv("_TAKOYAKI_EXEC_NS_FDS");

    /* Stage 2: we are the re-exec'd workload. Only the mnt join is left; it
     * had to wait until after the execve below so ld.so could still resolve
     * libc/libseccomp on the host, and it must happen before SubstrateVM
     * spawns its runtime threads.
     *
     * Before cutting ourselves off from the host filesystem, warm the dynamic
     * loader with the libraries SubstrateVM's FFM lookup dlopens lazily at
     * first use (RuntimeSystemLookup wants libm). A minimal container rootfs
     * (busybox, distroless) has no glibc at all, but dlopen by soname returns
     * the already-loaded copy without touching the filesystem. */
    if (getenv("_TAKOYAKI_EXEC_STAGE2")) {
        static const char *const preload[] = {
            "libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1",
        };
        for (size_t i = 0; i < sizeof(preload) / sizeof(preload[0]); i++) {
            if (!dlopen(preload[i], RTLD_NOW | RTLD_GLOBAL)) {
                fprintf(stderr, "[exec-bootstrap] preload %s failed: %s\n",
                        preload[i], dlerror());
            }
        }
        if (ns_env && *ns_env) {
            exec_setns_pass(ns_env, 1);
        }
        return;
    }

    /* Stage 1: join everything except mnt (mnt now would cut us off from the
     * host libraries the stage-2 execve still needs to load). */
    if (ns_env && *ns_env) {
        exec_setns_pass(ns_env, 0);
    }

    pid_t workload_pid = clone_parent();
    if (workload_pid < 0) {
        fprintf(stderr, "[exec-bootstrap] clone failed: %s\n", strerror(errno));
        exit(1);
    }
    if (workload_pid > 0) {
        /* Intermediate: hand the workload pid to the CLI and get out of the
         * way. Same int32 wire format MainProcess already reads for the
         * create path's stage-2 pid. */
        if (write(sync_fd, &workload_pid, sizeof(workload_pid)) != sizeof(workload_pid)) {
            fprintf(stderr, "[exec-bootstrap] pid report failed: %s\n", strerror(errno));
            _exit(1);
        }
        _exit(0);
    }

    /* Workload: re-exec ourselves before running any runtime code. The raw
     * clone above bypasses glibc's fork path, so libc state cached in TLS
     * (the tid, notably) still describes the parent — SubstrateVM would then
     * call sched_getaffinity(stale-tid) and die with ESRCH, since that number
     * does not exist inside the container pid ns we were born into. execve
     * rebuilds libc from scratch for our real pid. The create path's stage-2
     * re-execs after its raw clone for the same reason. */
    DBG("child process in init()\n");
    if (setenv("_TAKOYAKI_EXEC_STAGE2", "1", 1) != 0) {
        fprintf(stderr, "[exec-bootstrap] setenv failed: %s\n", strerror(errno));
        _exit(1);
    }
    char *const argv[] = {(char *) "/proc/self/exe", (char *) "__exec__", NULL};
    extern char **environ;
    execve("/proc/self/exe", argv, environ);
    fprintf(stderr, "[exec-bootstrap] re-exec failed: %s\n", strerror(errno));
    _exit(1);
}

__attribute__((constructor))
void takoyaki_bootstrap(void) {
    int sync_fd;
    int sync_pipe[2];
    pid_t stage2_pid = -1;
    enum sync_t s;
    unsigned int clone_flags;

    /* Ignore SIGPIPE so that writing to a broken pipe (e.g. a log fd whose
     * reader has closed) returns EPIPE instead of terminating the process.
     * Without this, a stale pipe can silently kill the init before it
     * finishes the sync handshake, causing flaky test failures. runc's Go
     * runtime ignores SIGPIPE by default; we match that here. */
    signal(SIGPIPE, SIG_IGN);

    /* Stamp the earliest reachable timestamp. The constructor runs from the
     * dynamic linker's init_array before main(), so this captures everything
     * the loader, libc, glibc relocation, and SubstrateVM heap mapping cost
     * us. When _TAKOYAKI_TRACE_STARTUP=1 we also dump the value so the Java
     * trace block can subtract it from System.nanoTime() at main() entry. */
    if (!t0_set) {
        clock_gettime(CLOCK_MONOTONIC, &t0_constructor);
        t0_set = 1;
        if (getenv("_TAKOYAKI_TRACE_STARTUP")) {
            long ns = (long) t0_constructor.tv_sec * 1000000000L + (long) t0_constructor.tv_nsec;
            fprintf(stderr, "[trace] CTOR raw monotonic ns     : %ld\n", ns);
        }
    }

    if (!getenv(ENV_IS_BOOTSTRAP)) {
        exec_bootstrap();
        return;
    }

    debug_enabled = getenv(ENV_DEBUG) != NULL;

    /* Redirect stderr to the log file so that DBG() and error messages from
     * bootstrap.c go to the same place as the Java Logger output. Without
     * this, bootstrap debug lines leak to the terminal and cause bats tests
     * like "global --debug to --log" to fail. */
    {
        const char *log_file = getenv("_TAKOYAKI_LOG_FILE");
        if (log_file) {
            int log_fd = open(log_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (log_fd >= 0) {
                dup2(log_fd, STDERR_FILENO);
                close(log_fd);
            }
        }
    }

    DBG("nsexec container setup\n");
    log_cpu_affinity();
    DBG("[stage-1] starting namespace setup\n");

    clone_flags = getenv_uint_hex(ENV_CLONE_FLAGS);
    DBG("[stage-1] clone flags: 0x%x\n", clone_flags);

    sync_fd = getenv_int(ENV_SYNCPIPE);
    if (sync_fd < 0) {
        fprintf(stderr, "[stage-1] missing %s env var\n", ENV_SYNCPIPE);
        exit(1);
    }
    DBG("[stage-1] sync fd: %d\n", sync_fd);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sync_pipe) < 0) {
        fprintf(stderr, "[stage-1] socketpair failed: %s\n", strerror(errno));
        exit(1);
    }

    /* Join existing namespaces specified via spec.linux.namespaces[].path.
     * CreateCommand opens the path on the host (host's /proc) and passes the
     * fds through _TAKOYAKI_NS_FDS=type:fd,type:fd,... so we can call setns
     * here before any unshare. Format mirrors the env var written in
     * CreateCommand.
     *
     * Three-pass approach (matching runc's join_namespaces):
     *   Pass 1: non-user namespaces (while still in init userns with host caps)
     *           EPERM is silently skipped because the namespace might be owned
     *           by the target userns we haven't joined yet.
     *   Pass 2: user namespace (switches to target userns)
     *   Pass 3: retry non-user namespaces that got EPERM in pass 1, now that
     *           we are in the target userns and have its capabilities.
     *
     * This handles containers that join some externally-created namespace
     * alongside an unrelated user namespace. */
#define MAX_NS_FDS 16
    struct ns_entry {
        char type[16];
        int fd;
        int nstype;
        int joined;
    };
    struct ns_entry ns_entries[MAX_NS_FDS];
    int ns_count = 0;
    int joined_userns = 0;

    char *ns_fds_env = getenv("_TAKOYAKI_NS_FDS");
    if (ns_fds_env && *ns_fds_env) {
        char *copy = strdup(ns_fds_env);
        if (!copy) {
            fprintf(stderr, "[stage-1] strdup ns_fds_env failed\n");
            exit(1);
        }
        /* Parse the entries. */
        char *saveptr = NULL;
        char *token = strtok_r(copy, ",", &saveptr);
        while (token && ns_count < MAX_NS_FDS) {
            char *colon = strchr(token, ':');
            if (colon) {
                *colon = '\0';
                struct ns_entry *e = &ns_entries[ns_count];
                snprintf(e->type, sizeof(e->type), "%s", token);
                e->fd = atoi(colon + 1);
                e->joined = 0;
                if      (strcmp(e->type, "user")    == 0) e->nstype = CLONE_NEWUSER;
                else if (strcmp(e->type, "ipc")     == 0) e->nstype = CLONE_NEWIPC;
                else if (strcmp(e->type, "uts")     == 0) e->nstype = CLONE_NEWUTS;
                else if (strcmp(e->type, "network") == 0) e->nstype = CLONE_NEWNET;
                else if (strcmp(e->type, "pid")     == 0) e->nstype = CLONE_NEWPID;
                else if (strcmp(e->type, "mount")   == 0) e->nstype = CLONE_NEWNS;
                else if (strcmp(e->type, "cgroup")  == 0) e->nstype = CLONE_NEWCGROUP;
                else if (strcmp(e->type, "time")    == 0) e->nstype = CLONE_NEWTIME;
                else e->nstype = 0;
                ns_count++;
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(copy);

        /* Pass 1: join non-user namespaces (EPERM silently skipped). */
        for (int i = 0; i < ns_count; i++) {
            struct ns_entry *e = &ns_entries[i];
            if (e->nstype == CLONE_NEWUSER) continue;
            DBG("[stage-1] setns(fd=%d, %s) [pass 1]\n", e->fd, e->type);
            if (setns(e->fd, e->nstype) < 0) {
                if (errno == EPERM) {
                    DBG("[stage-1] setns(%s) EPERM, will retry after userns join\n", e->type);
                    continue;
                }
                fprintf(stderr, "[stage-1] setns(%s, fd=%d) failed: %s\n",
                        e->type, e->fd, strerror(errno));
                exit(1);
            }
            e->joined = 1;
            close(e->fd);
            e->fd = -1;
        }

        /* Pass 2: join user namespace. */
        for (int i = 0; i < ns_count; i++) {
            struct ns_entry *e = &ns_entries[i];
            if (e->nstype != CLONE_NEWUSER) continue;
            DBG("[stage-1] setns(fd=%d, %s) [pass 2]\n", e->fd, e->type);
            if (setns(e->fd, e->nstype) < 0) {
                fprintf(stderr, "[stage-1] setns(%s, fd=%d) failed: %s\n",
                        e->type, e->fd, strerror(errno));
                exit(1);
            }
            e->joined = 1;
            joined_userns = 1;
            close(e->fd);
            e->fd = -1;
            /* setns(CLONE_NEWUSER) clears effective capabilities.
             * Become root in the joined userns to restore them (matching
             * runc's setresuid(0,0,0) after user namespace join). */
            if (setresuid(0, 0, 0) < 0) {
                fprintf(stderr, "[stage-1] setresuid(0,0,0) after userns join failed: %s\n",
                        strerror(errno));
                exit(1);
            }
            if (setresgid(0, 0, 0) < 0) {
                fprintf(stderr, "[stage-1] setresgid(0,0,0) after userns join failed: %s\n",
                        strerror(errno));
                exit(1);
            }
            DBG("[stage-1] now root in joined user namespace\n");
        }

        /* Pass 3: retry non-user namespaces skipped with EPERM. */
        for (int i = 0; i < ns_count; i++) {
            struct ns_entry *e = &ns_entries[i];
            if (e->joined || e->nstype == CLONE_NEWUSER) continue;
            DBG("[stage-1] setns(fd=%d, %s) [pass 3]\n", e->fd, e->type);
            if (setns(e->fd, e->nstype) < 0) {
                fprintf(stderr, "[stage-1] setns(%s, fd=%d) failed: %s\n",
                        e->type, e->fd, strerror(errno));
                exit(1);
            }
            e->joined = 1;
            close(e->fd);
            e->fd = -1;
        }
    }

    if (clone_flags & CLONE_NEWUSER) {
        DBG("[stage-1] unshare(CLONE_NEWUSER)\n");
        if (unshare(CLONE_NEWUSER) < 0) {
            fprintf(stderr, "[stage-1] unshare(CLONE_NEWUSER) failed: %s\n", strerror(errno));
            exit(1);
        }
        if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
            fprintf(stderr, "[stage-1] prctl(PR_SET_DUMPABLE,1) failed: %s\n", strerror(errno));
            exit(1);
        }
        s = SYNC_USERMAP_PLS;
        if (write(sync_fd, &s, sizeof(s)) != sizeof(s)) {
            fprintf(stderr, "[stage-1] write SYNC_USERMAP_PLS failed: %s\n", strerror(errno));
            exit(1);
        }
        pid_t my_pid = getpid();
        if (write(sync_fd, &my_pid, sizeof(my_pid)) != sizeof(my_pid)) {
            fprintf(stderr, "[stage-1] write pid failed: %s\n", strerror(errno));
            exit(1);
        }
        if (read(sync_fd, &s, sizeof(s)) != sizeof(s)) {
            fprintf(stderr, "[stage-1] read SYNC_USERMAP_ACK failed: %s\n", strerror(errno));
            exit(1);
        }
        if (s != SYNC_USERMAP_ACK) {
            fprintf(stderr, "[stage-1] expected SYNC_USERMAP_ACK, got 0x%x\n", s);
            exit(1);
        }
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) {
            fprintf(stderr, "[stage-1] prctl(PR_SET_DUMPABLE,0) failed: %s\n", strerror(errno));
            exit(1);
        }
        if (setuid(0) < 0) {
            fprintf(stderr, "[stage-1] setuid(0) failed: %s\n", strerror(errno));
            exit(1);
        }
        if (setgid(0) < 0) {
            fprintf(stderr, "[stage-1] setgid(0) failed: %s\n", strerror(errno));
            exit(1);
        }
        DBG("[stage-1] now root in user namespace\n");
    }

    /* CLONE_NEWCGROUP is NOT unshared here. The cgroup namespace root is
     * captured at unshare time, and we need the init process to be in the
     * container's cgroup first (via addPid). Stage-1 waits for the parent's
     * CGROUP_ACK, then stage-2 calls unshare(CLONE_NEWCGROUP). */
    if (clone_flags & CLONE_NEWNS) {
        DBG("[stage-1] unshare(CLONE_NEWNS)\n");
        if (unshare(CLONE_NEWNS) < 0) {
            fprintf(stderr, "[stage-1] unshare(CLONE_NEWNS) failed: %s\n", strerror(errno));
            exit(1);
        }
    }
    if (clone_flags & CLONE_NEWNET) {
        DBG("[stage-1] unshare(CLONE_NEWNET)\n");
        if (unshare(CLONE_NEWNET) < 0) {
            fprintf(stderr, "[stage-1] unshare(CLONE_NEWNET) failed: %s\n", strerror(errno));
            exit(1);
        }
    }
    if (clone_flags & CLONE_NEWUTS) {
        DBG("[stage-1] unshare(CLONE_NEWUTS)\n");
        if (unshare(CLONE_NEWUTS) < 0) {
            fprintf(stderr, "[stage-1] unshare(CLONE_NEWUTS) failed: %s\n", strerror(errno));
            exit(1);
        }
    }
    if (clone_flags & CLONE_NEWIPC) {
        DBG("[stage-1] unshare(CLONE_NEWIPC)\n");
        if (unshare(CLONE_NEWIPC) < 0) {
            fprintf(stderr, "[stage-1] unshare(CLONE_NEWIPC) failed: %s\n", strerror(errno));
            exit(1);
        }
    }
    /* time namespace must be unshared BEFORE pid namespace because once the new
     * pid_for_children namespace is set the kernel won't accept time NS changes. */
    if (clone_flags & CLONE_NEWTIME) {
        DBG("[stage-1] unshare(CLONE_NEWTIME)\n");
        if (unshare(CLONE_NEWTIME) < 0) {
            fprintf(stderr, "[stage-1] unshare(CLONE_NEWTIME) failed: %s\n", strerror(errno));
            exit(1);
        }
        /* /proc/self/timens_offsets is writable ONLY while the writer task has not
         * exec'd in the new time namespace. Bootstrap stage-1 has not yet exec'd
         * after the unshare, so it's allowed here. The Java init cannot do this
         * itself because by then it has already exec'd into a new binary, and
         * gettimeofday calls during JVM startup would lock the offsets anyway.
         * Values come through env vars set by CreateCommand. */
        char *bt_s = getenv("_TAKOYAKI_TIMENS_BOOTTIME_SECS");
        char *bt_n = getenv("_TAKOYAKI_TIMENS_BOOTTIME_NSEC");
        char *mt_s = getenv("_TAKOYAKI_TIMENS_MONOTONIC_SECS");
        char *mt_n = getenv("_TAKOYAKI_TIMENS_MONOTONIC_NSEC");
        if (bt_s || mt_s) {
            char buf[256];
            int len = 0;
            if (bt_s) {
                len += snprintf(buf + len, sizeof(buf) - len, "boottime %s %s\n",
                                bt_s, bt_n ? bt_n : "0");
            }
            if (mt_s) {
                len += snprintf(buf + len, sizeof(buf) - len, "monotonic %s %s\n",
                                mt_s, mt_n ? mt_n : "0");
            }
            /* In a user namespace, prctl(PR_SET_DUMPABLE, 0) makes /proc/self
             * inaccessible (owned by root in the INIT userns). Temporarily
             * restore dumpability so we can write timens_offsets, then clear
             * it again. Outside a userns this is harmless. */
            if (clone_flags & CLONE_NEWUSER) {
                prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
            }
            int fd = open("/proc/self/timens_offsets", O_WRONLY);
            if (fd < 0) {
                fprintf(stderr, "[stage-1] open timens_offsets failed: %s\n",
                        strerror(errno));
            } else {
                if (write(fd, buf, len) != len) {
                    fprintf(stderr, "[stage-1] write timens_offsets failed: %s\n",
                            strerror(errno));
                } else {
                    DBG("[stage-1] timens_offsets applied: %.*s", len, buf);
                }
                close(fd);
            }
            if (clone_flags & CLONE_NEWUSER) {
                prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
        }
    }
    if (clone_flags & CLONE_NEWPID) {
        DBG("[stage-1] unshare(CLONE_NEWPID)\n");
        if (unshare(CLONE_NEWPID) < 0) {
            fprintf(stderr, "[stage-1] unshare(CLONE_NEWPID) failed: %s\n", strerror(errno));
            exit(1);
        }
    }

    DBG("[stage-1] cloning stage-2 with CLONE_PARENT\n");
    stage2_pid = clone_parent();

    if (stage2_pid < 0) {
        fprintf(stderr, "[stage-1] clone failed: %s\n", strerror(errno));
        exit(1);
    }

    if (stage2_pid == 0) {
        close(sync_pipe[1]);
        close(sync_fd);
        DBG("[stage-2] started, pid=%d\n", getpid());
        if (read(sync_pipe[0], &s, sizeof(s)) != sizeof(s)) {
            fprintf(stderr, "[stage-2] read SYNC_GRANDCHILD failed: %s\n", strerror(errno));
            _exit(1);
        }
        if (s != SYNC_GRANDCHILD) {
            fprintf(stderr, "[stage-2] expected SYNC_GRANDCHILD, got 0x%x\n", s);
            _exit(1);
        }
        /* Create the cgroup namespace NOW, after the parent has moved us into
         * the container's cgroup. This ensures the cgroupns root is the
         * container's cgroup, so /proc/self/cgroup shows "0::/" inside. */
        if (clone_flags & CLONE_NEWCGROUP) {
            DBG("[stage-2] unshare(CLONE_NEWCGROUP)\n");
            if (unshare(CLONE_NEWCGROUP) < 0) {
                fprintf(stderr, "[stage-2] unshare(CLONE_NEWCGROUP) failed: %s\n", strerror(errno));
                _exit(1);
            }
        }
        if (setsid() < 0) {
            fprintf(stderr, "[stage-2] setsid failed: %s\n", strerror(errno));
            _exit(1);
        }
        s = SYNC_CHILD_FINISH;
        if (write(sync_pipe[0], &s, sizeof(s)) != sizeof(s)) {
            fprintf(stderr, "[stage-2] write SYNC_CHILD_FINISH failed: %s\n", strerror(errno));
            _exit(1);
        }
        close(sync_pipe[0]);
        DBG("child process in init()\n");

        /* Unset bootstrap-related env so the new process runs Java runtime fresh
         * as the init process (detected via args[0] == "__init__"). */
        unsetenv(ENV_IS_BOOTSTRAP);
        unsetenv(ENV_SYNCPIPE);
        unsetenv(ENV_CLONE_FLAGS);

        /* Close all fds >= 3 (except those the Java init needs, which are
         * passed via env vars). Mark them CLOEXEC first, then clear the flag
         * on the fds that must survive execve. This prevents stray fds
         * (e.g. bats output) from leaking into the container process. */
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
        if (syscall(SYS_close_range, 3, ~0U, CLOSE_RANGE_CLOEXEC) == 0) {
            /* Clear CLOEXEC on fds that the Java init reads from env vars. */
            char *env_val;
            int keep_fd;
            const char *keep_vars[] = {
                "_TAKOYAKI_MAIN_SENDER_FD",
                "_TAKOYAKI_NOTIFY_LISTENER_FD",
                "_TAKOYAKI_SECCOMP_LISTENER_FD",
                "_TAKOYAKI_CONSOLE_SOCKET_FD",
                NULL
            };
            for (int i = 0; keep_vars[i]; i++) {
                env_val = getenv(keep_vars[i]);
                if (env_val) {
                    keep_fd = atoi(env_val);
                    if (keep_fd >= 3) {
                        int fl = fcntl(keep_fd, F_GETFD, 0);
                        if (fl != -1) fcntl(keep_fd, F_SETFD, fl & ~FD_CLOEXEC);
                    }
                }
            }
            /* _TAKOYAKI_IDMAP_FDS has a multi-fd format:
             *   base64(dest):fd,base64(dest):fd,...
             * Extract each fd number and clear CLOEXEC. */
            env_val = getenv("_TAKOYAKI_IDMAP_FDS");
            if (env_val) {
                char *copy = strdup(env_val);
                if (copy) {
                    char *saveptr, *token;
                    for (token = strtok_r(copy, ",", &saveptr);
                         token;
                         token = strtok_r(NULL, ",", &saveptr)) {
                        char *colon = strchr(token, ':');
                        if (colon) {
                            keep_fd = atoi(colon + 1);
                            if (keep_fd >= 3) {
                                int fl = fcntl(keep_fd, F_GETFD, 0);
                                if (fl != -1) fcntl(keep_fd, F_SETFD, fl & ~FD_CLOEXEC);
                            }
                        }
                    }
                    free(copy);
                }
            }
            /* _TAKOYAKI_IDMAP_USERNS_FDS has format:
             *   base64(dest):usernsFd:recursive,...
             * Extract the userns fd (second colon-separated field). */
            env_val = getenv("_TAKOYAKI_IDMAP_USERNS_FDS");
            if (env_val) {
                char *copy = strdup(env_val);
                if (copy) {
                    char *saveptr, *token;
                    for (token = strtok_r(copy, ",", &saveptr);
                         token;
                         token = strtok_r(NULL, ",", &saveptr)) {
                        char *colon = strchr(token, ':');
                        if (colon) {
                            keep_fd = atoi(colon + 1);
                            if (keep_fd >= 3) {
                                int fl = fcntl(keep_fd, F_GETFD, 0);
                                if (fl != -1) fcntl(keep_fd, F_SETFD, fl & ~FD_CLOEXEC);
                            }
                        }
                    }
                    free(copy);
                }
            }
            /* _TAKOYAKI_BIND_SOURCE_FDS has format:
             *   base64(dest):fd,...
             * Extract the fd (second colon-separated field). */
            env_val = getenv("_TAKOYAKI_BIND_SOURCE_FDS");
            if (env_val) {
                char *copy = strdup(env_val);
                if (copy) {
                    char *saveptr, *token;
                    for (token = strtok_r(copy, ",", &saveptr);
                         token;
                         token = strtok_r(NULL, ",", &saveptr)) {
                        char *colon = strchr(token, ':');
                        if (colon) {
                            keep_fd = atoi(colon + 1);
                            if (keep_fd >= 3) {
                                int fl = fcntl(keep_fd, F_GETFD, 0);
                                if (fl != -1) fcntl(keep_fd, F_SETFD, fl & ~FD_CLOEXEC);
                            }
                        }
                    }
                    free(copy);
                }
            }
            DBG("[stage-2] CLOEXEC set on fds >= 3 (kept needed fds)\n");
        } else {
            DBG("[stage-2] close_range CLOEXEC not available: %s\n", strerror(errno));
        }

        DBG("[stage-2] execve(/proc/self/exe __init__) to start fresh runtime\n");
        char *argv[] = { "takoyaki", "__init__", NULL };
        execv("/proc/self/exe", argv);
        fprintf(stderr, "[stage-2] execv failed: %s\n", strerror(errno));
        _exit(1);
    }

    close(sync_pipe[0]);
    DBG("[stage-1] forked stage-2 pid=%d\n", stage2_pid);

    if (write(sync_fd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
        fprintf(stderr, "[stage-1] write stage-2 pid failed: %s\n", strerror(errno));
        exit(1);
    }

    /* Wait for the parent to move the init process into the container's
     * cgroup (addPid). Stage-2 will unshare CLONE_NEWCGROUP after this
     * so the cgroupns root is the container's cgroup, not the parent's. */
    if (clone_flags & CLONE_NEWCGROUP) {
        if (read(sync_fd, &s, sizeof(s)) != sizeof(s)) {
            fprintf(stderr, "[stage-1] read SYNC_CGROUP_ACK failed: %s\n", strerror(errno));
            exit(1);
        }
        if (s != SYNC_CGROUP_ACK) {
            fprintf(stderr, "[stage-1] expected SYNC_CGROUP_ACK, got 0x%x\n", s);
            exit(1);
        }
        DBG("[stage-1] received CGROUP_ACK from parent\n");
    }

    s = SYNC_GRANDCHILD;
    if (write(sync_pipe[1], &s, sizeof(s)) != sizeof(s)) {
        fprintf(stderr, "[stage-1] write SYNC_GRANDCHILD failed: %s\n", strerror(errno));
        exit(1);
    }
    if (read(sync_pipe[1], &s, sizeof(s)) != sizeof(s)) {
        fprintf(stderr, "[stage-1] read SYNC_CHILD_FINISH failed: %s\n", strerror(errno));
        exit(1);
    }
    if (s != SYNC_CHILD_FINISH) {
        fprintf(stderr, "[stage-1] expected SYNC_CHILD_FINISH, got 0x%x\n", s);
        exit(1);
    }

    close(sync_pipe[1]);
    close(sync_fd);
    DBG("[stage-1] exiting; stage-2 continues as init\n");
    _exit(0);
}

/*
 * Fork a helper child that unshares CLONE_NEWUSER and synchronises with
 * the parent via a pre-created socketpair.  Returns the child PID to the
 * parent, or -1 on fork failure.  The child never returns.
 *
 * This MUST live in C because PosixIO.fork() leaves the child inside a
 * SubstrateVM process whose runtime threads (GC, signal handler) did not
 * survive fork().  Any Java object allocation in the child triggers a GC
 * safepoint that waits for those dead threads, producing an infinite
 * 1 ms nanosleep spin (the root cause of the ARM CI idmap hang).  By
 * keeping the child path in plain C with all signals blocked we sidestep
 * SubstrateVM entirely.
 *
 * @param parent_fd  the socketpair end the PARENT reads from (closed by
 *                   the child so the parent sees EOF on child death)
 * @param child_fd   the socketpair end the CHILD uses for sync I/O
 */
int takoyaki_idmap_helper_fork(int parent_fd, int child_fd) {
    pid_t pid = fork();
    if (pid != 0) return pid;   /* parent: child pid, or -1 on error */

    /* ── child ────────────────────────────────────────────────────── */

    /* Block every deliverable signal.  SubstrateVM installs handlers
     * (SIGSEGV for safepoints, SIGUSR1, timers) that try to coordinate
     * with runtime threads which no longer exist after fork(). */
    sigset_t full;
    sigfillset(&full);
    sigprocmask(SIG_BLOCK, &full, NULL);

    close(parent_fd);

    int rc = unshare(CLONE_NEWUSER);
    char c = (rc == 0) ? 1 : 0;
    (void)write(child_fd, &c, 1);

    if (rc != 0) _exit(1);

    /* Wait until the parent has written uid_map / gid_map. */
    (void)read(child_fd, &c, 1);
    _exit(0);
}

