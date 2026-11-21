#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>

/*
 * Fixed-arity wrappers for the variadic libc functions takoyaki calls.
 * @CFunction does not support the varargs calling convention, so the
 * generated NativeH calls these instead (see GenerateFastBindings); the C
 * compiler then emits the variadic call correctly for the platform.
 */

int takoyaki_prctl(int option, long a2, long a3, long a4, long a5) {
    return prctl(option, a2, a3, a4, a5);
}

long takoyaki_syscall(long number, long a1, long a2, long a3, long a4, long a5) {
    return syscall(number, a1, a2, a3, a4, a5);
}

int takoyaki_ioctl(int fd, unsigned long request, void *arg) {
    return ioctl(fd, request, arg);
}

int takoyaki_open(const char *path, int flags, int mode) {
    return open(path, flags, mode);
}

int takoyaki_fcntl(int fd, int cmd, int arg) {
    return fcntl(fd, cmd, arg);
}
