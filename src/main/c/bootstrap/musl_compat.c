#define _GNU_SOURCE
#include <sys/resource.h>

/*
 * @CFunction names the glibc symbol, but musl 1.2.4 keeps the LFS64 names
 * only as header macros, so libc.a has no prlimit64.
 */
#undef prlimit64
int prlimit64(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit) {
    return prlimit(pid, resource, new_limit, old_limit);
}
