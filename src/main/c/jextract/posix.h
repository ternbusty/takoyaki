/*
 * Headers backing the generated PosixH bindings: the socket/IO entry points
 * plus the structs used for SCM_RIGHTS fd passing (msghdr / iovec / cmsghdr)
 * and unix socket addressing (sockaddr_un). See the jextractPosix gradle task.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>
