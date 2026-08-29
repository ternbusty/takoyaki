package com.ternbusty.takoyaki.ipc

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.gen.NativeH
import com.ternbusty.takoyaki.syscall.gen.cmsghdr
import com.ternbusty.takoyaki.syscall.gen.iovec
import com.ternbusty.takoyaki.syscall.gen.msghdr
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * Pass open file descriptors over a unix domain socket using SCM_RIGHTS.
 *
 * Used for two things in takoyaki:
 * 1. Console socket: ship a pty master fd back to whoever invoked the runtime.
 * 2. Seccomp notify: forward the notify fd to the listener path.
 *
 * Struct layouts come from the jextract-generated [msghdr] / [iovec]
 * / [cmsghdr], so field offsets follow the system headers rather than
 * hand-computed constants.
 */
object ScmRights {

    /** Bytes a cmsghdr carrying one fd occupies, including trailing alignment. */
    private val CMSG_LEN_ONE_FD: Long = cmsghdr.sizeof() + Integer.BYTES
    private val CMSG_SPACE_ONE_FD: Long = align8(CMSG_LEN_ONE_FD)
    /** The fd payload sits immediately after the cmsghdr header. */
    private val CMSG_DATA_OFFSET: Long = cmsghdr.sizeof()

    private fun align8(n: Long): Long = (n + 7) and 7L.inv()

    /** Point msg at a single-byte iovec plus a control buffer, like the C macros do. */
    private fun buildMsg(arena: Arena, iovBuf: MemorySegment, cmsg: MemorySegment): MemorySegment {
        val iov = iovec.allocate(arena)
        iovec.iov_base(iov, iovBuf)
        iovec.iov_len(iov, 1L)

        val msg = msghdr.allocate(arena)
        msghdr.msg_name(msg, MemorySegment.NULL)
        msghdr.msg_namelen(msg, 0)
        msghdr.msg_iov(msg, iov)
        msghdr.msg_iovlen(msg, 1L)
        msghdr.msg_control(msg, cmsg)
        msghdr.msg_controllen(msg, CMSG_SPACE_ONE_FD)
        msghdr.msg_flags(msg, 0)
        return msg
    }

    /** Send one byte (and [fd] via SCM_RIGHTS) to the connected socket. */
    fun sendFd(sockFd: Int, fd: Int, tag: Byte): Boolean {
        try {
            Arena.ofConfined().use { arena ->
                val iovBuf = arena.allocate(1)
                iovBuf.set(ValueLayout.JAVA_BYTE, 0, tag)

                val cmsg = arena.allocate(CMSG_SPACE_ONE_FD)
                cmsghdr.cmsg_len(cmsg, CMSG_LEN_ONE_FD)
                cmsghdr.cmsg_level(cmsg, NativeH.SOL_SOCKET())
                cmsghdr.cmsg_type(cmsg, NativeH.SCM_RIGHTS())
                cmsg.set(ValueLayout.JAVA_INT, CMSG_DATA_OFFSET, fd)

                val rc = NativeH.sendmsg(sockFd, buildMsg(arena, iovBuf, cmsg), 0)
                if (rc < 0) {
                    Logger.warn("sendmsg failed: ${Libc.strerror(Libc.errno())}")
                    return false
                }
                return true
            }
        } catch (t: Throwable) {
            Logger.warn("scmrights sendFd error: ${t.message}")
            return false
        }
    }

    /**
     * Send arbitrary data together with [fd] via SCM_RIGHTS in a single
     * `sendmsg` call. The seccomp notify protocol requires the
     * ContainerProcessState JSON and the notify fd to arrive in the same
     * kernel message so the receiver's `recvmsg` picks up both the
     * data payload and the ancillary fd atomically.
     */
    fun sendFdWithData(sockFd: Int, fd: Int, data: ByteArray): Boolean {
        try {
            Arena.ofConfined().use { arena ->
                val iovBuf = arena.allocateFrom(ValueLayout.JAVA_BYTE, *data)

                val iov = iovec.allocate(arena)
                iovec.iov_base(iov, iovBuf)
                iovec.iov_len(iov, data.size.toLong())

                val cmsg = arena.allocate(CMSG_SPACE_ONE_FD)
                cmsghdr.cmsg_len(cmsg, CMSG_LEN_ONE_FD)
                cmsghdr.cmsg_level(cmsg, NativeH.SOL_SOCKET())
                cmsghdr.cmsg_type(cmsg, NativeH.SCM_RIGHTS())
                cmsg.set(ValueLayout.JAVA_INT, CMSG_DATA_OFFSET, fd)

                val msg = msghdr.allocate(arena)
                msghdr.msg_name(msg, MemorySegment.NULL)
                msghdr.msg_namelen(msg, 0)
                msghdr.msg_iov(msg, iov)
                msghdr.msg_iovlen(msg, 1L)
                msghdr.msg_control(msg, cmsg)
                msghdr.msg_controllen(msg, CMSG_SPACE_ONE_FD)
                msghdr.msg_flags(msg, 0)

                val rc = NativeH.sendmsg(sockFd, msg, 0)
                if (rc < 0) {
                    Logger.warn("sendmsg (with data) failed: ${Libc.strerror(Libc.errno())}")
                    return false
                }
                return true
            }
        } catch (t: Throwable) {
            Logger.warn("scmrights sendFdWithData error: ${t.message}")
            return false
        }
    }

    /** Receive a single fd via SCM_RIGHTS. Returns -1 on failure. */
    fun recvFd(sockFd: Int): Int {
        try {
            Arena.ofConfined().use { arena ->
                val iovBuf = arena.allocate(1)
                val cmsg = arena.allocate(CMSG_SPACE_ONE_FD)

                val rc = NativeH.recvmsg(sockFd, buildMsg(arena, iovBuf, cmsg), 0)
                if (rc < 0) {
                    Logger.warn("recvmsg failed: ${Libc.strerror(Libc.errno())}")
                    return -1
                }
                val level = cmsghdr.cmsg_level(cmsg)
                val type = cmsghdr.cmsg_type(cmsg)
                if (level != NativeH.SOL_SOCKET() || type != NativeH.SCM_RIGHTS()) {
                    Logger.warn("recvmsg returned unexpected cmsg level=$level type=$type")
                    return -1
                }
                return cmsg.get(ValueLayout.JAVA_INT, CMSG_DATA_OFFSET)
            }
        } catch (t: Throwable) {
            Logger.warn("scmrights recvFd error: ${t.message}")
            return -1
        }
    }
}
