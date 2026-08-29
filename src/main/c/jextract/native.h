/*
 * Unified header for jextract. Covers libc, POSIX, seccomp and the
 * kernel/socket constants takoyaki uses. jextract is run once against this
 * file; unused declarations are eliminated by native-image DCE.
 */
#define _GNU_SOURCE

/* libc / POSIX */
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
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

/* kernel / device / namespace constants */
#include <linux/capability.h>
#include <linux/close_range.h>
#include <linux/keyctl.h>
#include <linux/sockios.h>
#include <net/if.h>

/* libseccomp */
#include <seccomp.h>

/*
 * SCMP_ACT_ERRNO / SCMP_ACT_TRACE are function-like macros that OR the errno
 * into the low 16 bits, so jextract cannot turn them into constants. Expanding
 * them with a zero argument inside an enum gives jextract something it can
 * emit, which keeps the base values header-derived instead of hard-coded.
 */
enum takoyaki_scmp_action_base {
    TAKOYAKI_SCMP_ACT_ERRNO_BASE = SCMP_ACT_ERRNO(0),
    TAKOYAKI_SCMP_ACT_TRACE_BASE = SCMP_ACT_TRACE(0),
};
