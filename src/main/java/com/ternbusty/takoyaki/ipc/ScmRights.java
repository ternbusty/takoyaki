package com.ternbusty.takoyaki.ipc;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.posix.PosixH;
import com.ternbusty.takoyaki.syscall.posix.cmsghdr;
import com.ternbusty.takoyaki.syscall.posix.iovec;
import com.ternbusty.takoyaki.syscall.posix.msghdr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * Pass open file descriptors over a unix domain socket using SCM_RIGHTS.
 *
 * Used for two things in takoyaki:
 * 1. Console socket: ship a pty master fd back to whoever invoked the runtime.
 * 2. Seccomp notify: forward the notify fd to the listener path.
 *
 * Struct layouts come from the jextract-generated {@link msghdr} / {@link iovec}
 * / {@link cmsghdr}, so field offsets follow the system headers rather than
 * hand-computed constants.
 */
public final class ScmRights {
    private ScmRights() {}

    /** Bytes a cmsghdr carrying one fd occupies, including trailing alignment. */
    private static final long CMSG_LEN_ONE_FD = cmsghdr.sizeof() + Integer.BYTES;
    private static final long CMSG_SPACE_ONE_FD = align8(CMSG_LEN_ONE_FD);
    /** The fd payload sits immediately after the cmsghdr header. */
    private static final long CMSG_DATA_OFFSET = cmsghdr.sizeof();

    private static long align8(long n) {
        return (n + 7) & ~7L;
    }

    /** Point msg at a single-byte iovec plus a control buffer, like the C macros do. */
    private static MemorySegment buildMsg(Arena arena, MemorySegment iovBuf, MemorySegment cmsg) {
        MemorySegment iov = iovec.allocate(arena);
        iovec.iov_base(iov, iovBuf);
        iovec.iov_len(iov, 1L);

        MemorySegment msg = msghdr.allocate(arena);
        msghdr.msg_name(msg, MemorySegment.NULL);
        msghdr.msg_namelen(msg, 0);
        msghdr.msg_iov(msg, iov);
        msghdr.msg_iovlen(msg, 1L);
        msghdr.msg_control(msg, cmsg);
        msghdr.msg_controllen(msg, CMSG_SPACE_ONE_FD);
        msghdr.msg_flags(msg, 0);
        return msg;
    }

    /** Send one byte (and {@code fd} via SCM_RIGHTS) to the connected socket. */
    public static boolean sendFd(int sockFd, int fd, byte tag) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment iovBuf = arena.allocate(1);
            iovBuf.set(ValueLayout.JAVA_BYTE, 0, tag);

            MemorySegment cmsg = arena.allocate(CMSG_SPACE_ONE_FD);
            cmsghdr.cmsg_len(cmsg, CMSG_LEN_ONE_FD);
            cmsghdr.cmsg_level(cmsg, PosixH.SOL_SOCKET());
            cmsghdr.cmsg_type(cmsg, PosixH.SCM_RIGHTS());
            cmsg.set(ValueLayout.JAVA_INT, CMSG_DATA_OFFSET, fd);

            long rc = PosixH.sendmsg(sockFd, buildMsg(arena, iovBuf, cmsg), 0);
            if (rc < 0) {
                Logger.warn("sendmsg failed: " + Libc.strerror(Libc.errno()));
                return false;
            }
            return true;
        } catch (Throwable t) {
            Logger.warn("scmrights sendFd error: " + t.getMessage());
            return false;
        }
    }

    /** Receive a single fd via SCM_RIGHTS. Returns -1 on failure. */
    public static int recvFd(int sockFd) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment iovBuf = arena.allocate(1);
            MemorySegment cmsg = arena.allocate(CMSG_SPACE_ONE_FD);

            long rc = PosixH.recvmsg(sockFd, buildMsg(arena, iovBuf, cmsg), 0);
            if (rc < 0) {
                Logger.warn("recvmsg failed: " + Libc.strerror(Libc.errno()));
                return -1;
            }
            int level = cmsghdr.cmsg_level(cmsg);
            int type = cmsghdr.cmsg_type(cmsg);
            if (level != PosixH.SOL_SOCKET() || type != PosixH.SCM_RIGHTS()) {
                Logger.warn("recvmsg returned unexpected cmsg level=" + level + " type=" + type);
                return -1;
            }
            return cmsg.get(ValueLayout.JAVA_INT, CMSG_DATA_OFFSET);
        } catch (Throwable t) {
            Logger.warn("scmrights recvFd error: " + t.getMessage());
            return -1;
        }
    }
}
