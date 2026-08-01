/*
 * Headers backing the generated Consts class (see the jextractConsts gradle
 * task). Values come from the build machine's headers, so syscall numbers and
 * arch-dependent flags need no hand-written `isAarch64() ? a : b`.
 */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <linux/capability.h>
#include <linux/close_range.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <linux/keyctl.h>
