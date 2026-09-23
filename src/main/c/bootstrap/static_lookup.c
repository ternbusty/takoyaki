/*
 * Symbol lookup table for fully-static (musl) builds where dlopen/dlsym
 * are non-functional.  Called from Java via SubstrateVM's @CFunction to
 * implement a SymbolLookup that works without a dynamic linker.
 *
 * Only symbols actually used by takoyaki are listed; jextract generates
 * bindings for hundreds of libc functions, but unused ones are never
 * resolved at runtime.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>

/* Only the symbol addresses are needed; avoid pulling in seccomp.h
 * (which requires kernel headers musl-dev does not ship). */
extern void *seccomp_arch_add();
extern void *seccomp_arch_resolve_name();
extern void *seccomp_attr_set();
extern void *seccomp_init();
extern void *seccomp_load();
extern void *seccomp_notify_fd();
extern void *seccomp_release();
extern void *seccomp_rule_add_array();
extern void *seccomp_syscall_resolve_name();

struct takoyaki_sym { const char *name; void *addr; };

static const struct takoyaki_sym sym_table[] = {
    /* libc */
    {"__errno_location", (void *)__errno_location},
    {"_exit",            (void *)_exit},
    {"accept",           (void *)accept},
    {"access",           (void *)access},
    {"bind",             (void *)bind},
    {"chdir",            (void *)chdir},
    {"chown",            (void *)chown},
    {"clearenv",         (void *)clearenv},
    {"close",            (void *)close},
    {"connect",          (void *)connect},
    {"dup2",             (void *)dup2},
    {"epoll_create1",    (void *)epoll_create1},
    {"epoll_ctl",        (void *)epoll_ctl},
    {"epoll_wait",       (void *)epoll_wait},
    {"execve",           (void *)execve},
    {"execvp",           (void *)execvp},
    {"fchdir",           (void *)fchdir},
    {"fcntl",            (void *)fcntl},
    {"fork",             (void *)fork},
    {"getegid",          (void *)getegid},
    {"geteuid",          (void *)geteuid},
    {"getpid",           (void *)getpid},
    {"getppid",          (void *)getppid},
    {"grantpt",          (void *)grantpt},
    {"ioctl",            (void *)ioctl},
    {"kill",             (void *)kill},
    {"listen",           (void *)listen},
    {"mknod",            (void *)mknod},
    {"mount",            (void *)mount},
    {"open",             (void *)open},
    {"pipe",             (void *)pipe},
    {"posix_openpt",     (void *)posix_openpt},
    {"prctl",            (void *)prctl},
    {"prlimit64",        (void *)prlimit64},
    {"ptsname_r",        (void *)ptsname_r},
    {"read",             (void *)read},
    {"readlink",         (void *)readlink},
    {"recv",             (void *)recv},
    {"recvmsg",          (void *)recvmsg},
    {"send",             (void *)send},
    {"sendmsg",          (void *)sendmsg},
    {"setdomainname",    (void *)setdomainname},
    {"setenv",           (void *)setenv},
    {"setgroups",        (void *)setgroups},
    {"sethostname",      (void *)sethostname},
    {"setns",            (void *)setns},
    {"setresgid",        (void *)setresgid},
    {"setresuid",        (void *)setresuid},
    {"setsid",           (void *)setsid},
    {"socket",           (void *)socket},
    {"socketpair",       (void *)socketpair},
    {"strerror",         (void *)strerror},
    {"syscall",          (void *)syscall},
    {"umask",            (void *)umask},
    {"umount2",          (void *)umount2},
    {"unlink",           (void *)unlink},
    {"unlockpt",         (void *)unlockpt},
    {"unshare",          (void *)unshare},
    {"waitpid",          (void *)waitpid},
    {"write",            (void *)write},
    /* libseccomp */
    {"seccomp_arch_add",            (void *)seccomp_arch_add},
    {"seccomp_arch_resolve_name",   (void *)seccomp_arch_resolve_name},
    {"seccomp_attr_set",            (void *)seccomp_attr_set},
    {"seccomp_init",                (void *)seccomp_init},
    {"seccomp_load",                (void *)seccomp_load},
    {"seccomp_notify_fd",           (void *)seccomp_notify_fd},
    {"seccomp_release",             (void *)seccomp_release},
    {"seccomp_rule_add_array",      (void *)seccomp_rule_add_array},
    {"seccomp_syscall_resolve_name", (void *)seccomp_syscall_resolve_name},
    {NULL, NULL}
};

void *takoyaki_static_lookup(const char *name) {
    for (const struct takoyaki_sym *e = sym_table; e->name; e++) {
        if (__builtin_expect(e->name[0] == name[0], 1) &&
            strcmp(e->name, name) == 0)
            return e->addr;
    }
    return NULL;
}
