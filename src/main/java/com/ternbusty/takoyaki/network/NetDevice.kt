package com.ternbusty.takoyaki.network

import com.ternbusty.takoyaki.logger.Logger
import com.ternbusty.takoyaki.spec.*
import com.ternbusty.takoyaki.syscall.Constants
import com.ternbusty.takoyaki.syscall.Libc
import com.ternbusty.takoyaki.syscall.PosixIO
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets

/**
 * Move network devices into the container's network namespace
 * and optionally rename them, using rtnetlink.
 */
object NetDevice {
    // Netlink constants
    private const val AF_NETLINK = 16
    private const val NETLINK_ROUTE = 0
    private const val RTM_SETLINK: Short = 19
    private const val NLM_F_REQUEST: Short = 1
    private const val NLM_F_ACK: Short = 4
    private const val IFLA_IFNAME: Short = 3
    private const val IFLA_NET_NS_PID: Short = 19

    // RTM_GETADDR / RTM_NEWADDR for address save/restore across netns moves.
    // The kernel strips all IPv4/IPv6 addresses when a device moves between
    // network namespaces. runc preserves permanent global-scope addresses by
    // listing them before the move and re-adding them in the target namespace.
    private const val RTM_NEWADDR: Short = 20
    private const val RTM_GETADDR: Short = 22
    private const val NLM_F_DUMP: Short = 0x300
    private const val NLM_F_CREATE: Short = 0x400
    private const val NLM_F_EXCL: Short = 0x200
    private const val NLMSG_DONE: Short = 3
    private const val NLMSG_ERROR: Short = 2
    private const val IFA_LOCAL: Short = 2
    private const val IFA_ADDRESS: Short = 1
    private const val IFA_FLAGS: Short = 8
    private const val IFA_F_PERMANENT = 0x80
    private const val RT_SCOPE_UNIVERSE = 0
    private const val IFADDRMSG_LEN = 8

    // ioctl for getting ifindex
    private const val SIOCGIFINDEX = 0x8933L

    // struct nlmsghdr size = 16, struct ifinfomsg size = 16
    private const val NLMSG_HDRLEN = 16
    private const val IFINFOMSG_LEN = 16

    /** A saved IPv4/IPv6 address to re-add after moving a device. */
    private data class SavedAddr(val family: Int, val prefixLen: Int, val address: ByteArray)

    /**
     * Move all devices listed in linux.netDevices to the container's net
     * namespace (identified by initPid). Called from the host (MainProcess)
     * after the init process has created its namespaces.
     */
    fun moveDevices(devices: Map<String, LinuxNetDevice>?, initPid: Int) {
        if (devices.isNullOrEmpty()) return

        Arena.ofConfined().use { arena ->
            for ((hostName, _) in devices) {
                val ifindex = getIfIndex(arena, hostName)
                if (ifindex <= 0) {
                    throw RuntimeException("failed to get ifindex for device $hostName")
                }

                // Save permanent global-scope addresses BEFORE the move.
                // The kernel strips all addresses when a device moves
                // between network namespaces.
                val savedAddrs = listPermanentGlobalAddrs(arena, ifindex)

                moveToNamespace(arena, ifindex, initPid)
                Logger.debug("moved $hostName (ifindex=$ifindex) to pid $initPid netns")

                // Re-add saved addresses and bring the interface UP
                // in the container's network namespace. The device still
                // has its original host name at this point (rename happens
                // later inside the container by renameDevices).
                reAddAddressesAndLinkUp(arena, initPid, hostName, savedAddrs)
            }
        }
    }

    /**
     * Rename devices inside the container's network namespace. Called from
     * InitProcess after namespace setup.
     */
    fun renameDevices(devices: Map<String, LinuxNetDevice>?) {
        if (devices.isNullOrEmpty()) return

        Arena.ofConfined().use { arena ->
            for ((hostName, dev) in devices) {
                val devName = dev.name
                if (!devName.isNullOrEmpty() && devName != hostName) {
                    val ifindex = getIfIndex(arena, hostName)
                    if (ifindex <= 0) {
                        Logger.warn("rename: device $hostName not found")
                        continue
                    }
                    renameDevice(arena, ifindex, devName)
                    Logger.debug("renamed $hostName to $devName")
                }
            }
        }
    }

    /** Look up ifindex for a network interface by name using ioctl. */
    private fun getIfIndex(arena: Arena, name: String): Int {
        val sock = PosixIO.socket(Constants.AF_INET, Constants.SOCK_DGRAM, 0)
        if (sock < 0) return -1
        try {
            // struct ifreq: 16 bytes name + 4 bytes ifindex + padding = 40 bytes
            val ifreq = arena.allocate(40)
            ifreq.fill(0.toByte())
            val nameBytes = name.toByteArray(StandardCharsets.UTF_8)
            for (i in 0 until minOf(nameBytes.size, 15)) {
                ifreq.set(ValueLayout.JAVA_BYTE, i.toLong(), nameBytes[i])
            }
            if (Libc.ioctl(sock, SIOCGIFINDEX, ifreq) != 0) {
                return -1
            }
            return ifreq.get(ValueLayout.JAVA_INT, 16)
        } finally {
            PosixIO.close(sock)
        }
    }

    /**
     * Move a device to another network namespace via rtnetlink.
     * Sends RTM_SETLINK with IFLA_NET_NS_PID.
     */
    private fun moveToNamespace(arena: Arena, ifindex: Int, nsPid: Int) {
        // NLA for IFLA_NET_NS_PID: rta_len=8 (4 header + 4 data), rta_type=IFLA_NET_NS_PID
        val nlaLen = 4 + 4 // rta header + u32
        val nlaPadded = align4(nlaLen)
        val totalLen = NLMSG_HDRLEN + IFINFOMSG_LEN + nlaPadded

        val msg = arena.allocate(totalLen.toLong())
        msg.fill(0.toByte())

        // nlmsghdr
        msg.set(ValueLayout.JAVA_INT, 0, totalLen)                                // nlmsg_len
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_SETLINK)                           // nlmsg_type
        msg.set(ValueLayout.JAVA_SHORT, 6, (NLM_F_REQUEST.toInt() or NLM_F_ACK.toInt()).toShort()) // nlmsg_flags
        msg.set(ValueLayout.JAVA_INT, 8, 1)                                       // nlmsg_seq
        msg.set(ValueLayout.JAVA_INT, 12, 0)                                      // nlmsg_pid

        // ifinfomsg
        msg.set(ValueLayout.JAVA_BYTE, NLMSG_HDRLEN.toLong(), 0.toByte())         // ifi_family
        msg.set(ValueLayout.JAVA_INT, (NLMSG_HDRLEN + 4).toLong(), ifindex)        // ifi_index

        // rtattr IFLA_NET_NS_PID
        val attrOff = NLMSG_HDRLEN + IFINFOMSG_LEN
        msg.set(ValueLayout.JAVA_SHORT, attrOff.toLong(), nlaLen.toShort())        // rta_len
        msg.set(ValueLayout.JAVA_SHORT, (attrOff + 2).toLong(), IFLA_NET_NS_PID)  // rta_type
        msg.set(ValueLayout.JAVA_INT, (attrOff + 4).toLong(), nsPid)               // pid value

        sendNetlink(arena, msg, totalLen)
    }

    /**
     * Rename a device via rtnetlink.
     * Sends RTM_SETLINK with IFLA_IFNAME.
     */
    private fun renameDevice(arena: Arena, ifindex: Int, newName: String) {
        val nameBytes = newName.toByteArray(StandardCharsets.UTF_8)
        val nlaLen = 4 + nameBytes.size + 1 // rta header + name + null terminator
        val nlaPadded = align4(nlaLen)
        val totalLen = NLMSG_HDRLEN + IFINFOMSG_LEN + nlaPadded

        val msg = arena.allocate(totalLen.toLong())
        msg.fill(0.toByte())

        // nlmsghdr
        msg.set(ValueLayout.JAVA_INT, 0, totalLen)
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_SETLINK)
        msg.set(ValueLayout.JAVA_SHORT, 6, (NLM_F_REQUEST.toInt() or NLM_F_ACK.toInt()).toShort())
        msg.set(ValueLayout.JAVA_INT, 8, 1)
        msg.set(ValueLayout.JAVA_INT, 12, 0)

        // ifinfomsg
        msg.set(ValueLayout.JAVA_BYTE, NLMSG_HDRLEN.toLong(), 0.toByte())
        msg.set(ValueLayout.JAVA_INT, (NLMSG_HDRLEN + 4).toLong(), ifindex)

        // rtattr IFLA_IFNAME
        val attrOff = NLMSG_HDRLEN + IFINFOMSG_LEN
        msg.set(ValueLayout.JAVA_SHORT, attrOff.toLong(), nlaLen.toShort())
        msg.set(ValueLayout.JAVA_SHORT, (attrOff + 2).toLong(), IFLA_IFNAME)
        for (i in nameBytes.indices) {
            msg.set(ValueLayout.JAVA_BYTE, (attrOff + 4 + i).toLong(), nameBytes[i])
        }

        sendNetlink(arena, msg, totalLen)
    }

    /** Open a netlink socket, send the message, read the ACK. */
    private fun sendNetlink(arena: Arena, msg: MemorySegment, len: Int) {
        val sock = PosixIO.socket(AF_NETLINK, Constants.SOCK_DGRAM, NETLINK_ROUTE)
        if (sock < 0) {
            throw RuntimeException("netlink socket: ${Libc.strerror(Libc.errno())}")
        }
        try {
            // Bind to kernel (pid=0, groups=0)
            // struct sockaddr_nl = { sa_family (2) + pad (2) + pid (4) + groups (4) } = 12
            val sa = arena.allocate(12)
            sa.fill(0.toByte())
            sa.set(ValueLayout.JAVA_SHORT, 0, AF_NETLINK.toShort())
            if (PosixIO.bindRaw(arena, sock, sa, 12) < 0) {
                throw RuntimeException("netlink bind: ${Libc.strerror(Libc.errno())}")
            }

            if (PosixIO.sendRaw(sock, msg, len.toLong(), 0) < 0) {
                throw RuntimeException("netlink send: ${Libc.strerror(Libc.errno())}")
            }

            // Read ACK (nlmsgerr). The kernel sends back a 36-byte message:
            // nlmsghdr(16) + int error(4) + original nlmsghdr(16)
            val ack = arena.allocate(1024)
            val n = PosixIO.recvRaw(sock, ack, 1024, 0)
            if (n < 20) {
                throw RuntimeException("netlink: no ack received")
            }
            val err = ack.get(ValueLayout.JAVA_INT, NLMSG_HDRLEN.toLong())
            if (err != 0) {
                throw RuntimeException("netlink: ${Libc.strerror(-err)}")
            }
        } finally {
            PosixIO.close(sock)
        }
    }

    /**
     * List permanent global-scope addresses on the given interface.
     * Called before a netns move so the addresses can be re-added afterwards.
     */
    private fun listPermanentGlobalAddrs(arena: Arena, ifindex: Int): List<SavedAddr> {
        val result = mutableListOf<SavedAddr>()
        val sock = PosixIO.socket(AF_NETLINK, Constants.SOCK_DGRAM, NETLINK_ROUTE)
        if (sock < 0) return result
        try {
            val sa = arena.allocate(12)
            sa.fill(0.toByte())
            sa.set(ValueLayout.JAVA_SHORT, 0, AF_NETLINK.toShort())
            if (PosixIO.bindRaw(arena, sock, sa, 12) < 0) return result

            // RTM_GETADDR dump request
            val reqLen = NLMSG_HDRLEN + IFADDRMSG_LEN
            val req = arena.allocate(reqLen.toLong())
            req.fill(0.toByte())
            req.set(ValueLayout.JAVA_INT, 0, reqLen)
            req.set(ValueLayout.JAVA_SHORT, 4, RTM_GETADDR)
            req.set(ValueLayout.JAVA_SHORT, 6, (NLM_F_REQUEST.toInt() or NLM_F_DUMP.toInt()).toShort())
            req.set(ValueLayout.JAVA_INT, 8, 1)
            if (PosixIO.sendRaw(sock, req, reqLen.toLong(), 0) < 0) return result

            val buf = arena.allocate(65536)
            var done = false
            while (!done) {
                val n = PosixIO.recvRaw(sock, buf, 65536, 0)
                if (n <= 0) break

                var offset = 0
                while (offset + NLMSG_HDRLEN <= n) {
                    val msgLen = buf.get(ValueLayout.JAVA_INT, offset.toLong())
                    if (msgLen < NLMSG_HDRLEN || offset + msgLen > n) break
                    val msgType = buf.get(ValueLayout.JAVA_SHORT, (offset + 4).toLong())

                    if (msgType == NLMSG_DONE) { done = true; break }
                    if (msgType == NLMSG_ERROR) { done = true; break }

                    if (msgType == RTM_NEWADDR &&
                        msgLen >= NLMSG_HDRLEN + IFADDRMSG_LEN
                    ) {
                        val base = offset + NLMSG_HDRLEN
                        val family = buf.get(ValueLayout.JAVA_BYTE, base.toLong()).toInt() and 0xFF
                        val prefLen = buf.get(ValueLayout.JAVA_BYTE, (base + 1).toLong()).toInt() and 0xFF
                        val ifaFlags = buf.get(ValueLayout.JAVA_BYTE, (base + 2).toLong()).toInt() and 0xFF
                        val scope = buf.get(ValueLayout.JAVA_BYTE, (base + 3).toLong()).toInt() and 0xFF
                        val index = buf.get(ValueLayout.JAVA_INT, (base + 4).toLong())

                        if (index == ifindex && scope == RT_SCOPE_UNIVERSE) {
                            var addrBytes: ByteArray? = null
                            var extFlags = ifaFlags
                            var attrOff = base + IFADDRMSG_LEN
                            val attrEnd = offset + align4(msgLen)

                            while (attrOff + 4 <= attrEnd) {
                                val rtaLen = buf.get(ValueLayout.JAVA_SHORT, attrOff.toLong()).toInt() and 0xFFFF
                                val rtaType = buf.get(ValueLayout.JAVA_SHORT, (attrOff + 2).toLong()).toInt() and 0xFFFF
                                if (rtaLen < 4) break
                                val dataLen = rtaLen - 4
                                if (rtaType == IFA_LOCAL.toInt() ||
                                    (rtaType == IFA_ADDRESS.toInt() && addrBytes == null)
                                ) {
                                    addrBytes = ByteArray(dataLen)
                                    MemorySegment.copy(
                                        buf, (attrOff + 4).toLong(),
                                        MemorySegment.ofArray(addrBytes), 0, dataLen.toLong()
                                    )
                                } else if (rtaType == IFA_FLAGS.toInt() && dataLen >= 4) {
                                    extFlags = buf.get(ValueLayout.JAVA_INT, (attrOff + 4).toLong())
                                }
                                attrOff += align4(rtaLen)
                            }

                            if (addrBytes != null && (extFlags and IFA_F_PERMANENT) != 0) {
                                result.add(SavedAddr(family, prefLen, addrBytes))
                                Logger.debug(
                                    "saved addr on ifindex $ifindex family=$family /$prefLen"
                                )
                            }
                        }
                    }
                    offset += align4(msgLen)
                }
            }
        } finally {
            PosixIO.close(sock)
        }
        return result
    }

    /**
     * Re-add saved addresses and bring the interface UP in the container's
     * network namespace. Creates a netlink socket inside the target namespace
     * via a temporary setns call, then operates through that socket from the
     * host namespace.
     */
    private fun reAddAddressesAndLinkUp(
        arena: Arena,
        initPid: Int,
        deviceName: String,
        savedAddrs: List<SavedAddr>
    ) {
        // Open namespace fds for the host and the container.
        val hostNsFd = PosixIO.open(arena, "/proc/self/ns/net", Constants.O_RDONLY, 0)
        if (hostNsFd < 0) {
            Logger.warn("cannot open host netns: ${Libc.strerror(Libc.errno())}")
            return
        }
        val containerNsFd = PosixIO.open(
            arena, "/proc/$initPid/ns/net", Constants.O_RDONLY, 0
        )
        if (containerNsFd < 0) {
            Logger.warn("cannot open container netns for pid $initPid")
            PosixIO.close(hostNsFd)
            return
        }

        // Enter the container's netns, create sockets there, then return.
        if (Libc.setns(containerNsFd, Constants.CLONE_NEWNET) != 0) {
            Logger.warn("setns to container netns failed: ${Libc.strerror(Libc.errno())}")
            PosixIO.close(hostNsFd)
            PosixIO.close(containerNsFd)
            return
        }
        val nlSock = PosixIO.socket(AF_NETLINK, Constants.SOCK_DGRAM, NETLINK_ROUTE)
        val newIfindex = getIfIndex(arena, deviceName)
        // Restore the host netns immediately.
        Libc.setns(hostNsFd, Constants.CLONE_NEWNET)
        PosixIO.close(hostNsFd)
        PosixIO.close(containerNsFd)

        if (nlSock < 0 || newIfindex <= 0) {
            Logger.warn(
                "failed to create netlink socket or find $deviceName in container netns"
            )
            if (nlSock >= 0) PosixIO.close(nlSock)
            return
        }

        try {
            // Bind the netlink socket (created in container's netns).
            val sa = arena.allocate(12)
            sa.fill(0.toByte())
            sa.set(ValueLayout.JAVA_SHORT, 0, AF_NETLINK.toShort())
            if (PosixIO.bindRaw(arena, nlSock, sa, 12) < 0) {
                Logger.warn("netlink bind in container ns failed")
                return
            }

            // Re-add each saved address.
            for (addr in savedAddrs) {
                addAddress(arena, nlSock, newIfindex, addr)
            }

            // Bring the interface UP.
            setLinkUp(arena, nlSock, newIfindex)
        } finally {
            PosixIO.close(nlSock)
        }
    }

    /** Send RTM_NEWADDR to add an address to the interface. */
    private fun addAddress(arena: Arena, sock: Int, ifindex: Int, addr: SavedAddr) {
        val addrLen = addr.address.size
        val nlaLocalLen = 4 + addrLen
        val nlaLocalPad = align4(nlaLocalLen)
        val nlaAddrLen = 4 + addrLen
        val nlaAddrPad = align4(nlaAddrLen)
        val totalLen = NLMSG_HDRLEN + IFADDRMSG_LEN + nlaLocalPad + nlaAddrPad

        val msg = arena.allocate(totalLen.toLong())
        msg.fill(0.toByte())

        // nlmsghdr
        msg.set(ValueLayout.JAVA_INT, 0, totalLen)
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_NEWADDR)
        msg.set(
            ValueLayout.JAVA_SHORT, 6,
            (NLM_F_REQUEST.toInt() or NLM_F_ACK.toInt() or NLM_F_CREATE.toInt() or NLM_F_EXCL.toInt()).toShort()
        )
        msg.set(ValueLayout.JAVA_INT, 8, 1)

        // ifaddrmsg
        val base = NLMSG_HDRLEN
        msg.set(ValueLayout.JAVA_BYTE, base.toLong(), addr.family.toByte())
        msg.set(ValueLayout.JAVA_BYTE, (base + 1).toLong(), addr.prefixLen.toByte())
        msg.set(ValueLayout.JAVA_BYTE, (base + 2).toLong(), 0.toByte())           // flags
        msg.set(ValueLayout.JAVA_BYTE, (base + 3).toLong(), RT_SCOPE_UNIVERSE.toByte())
        msg.set(ValueLayout.JAVA_INT, (base + 4).toLong(), ifindex)

        // IFA_LOCAL
        var off = NLMSG_HDRLEN + IFADDRMSG_LEN
        msg.set(ValueLayout.JAVA_SHORT, off.toLong(), nlaLocalLen.toShort())
        msg.set(ValueLayout.JAVA_SHORT, (off + 2).toLong(), IFA_LOCAL)
        MemorySegment.copy(MemorySegment.ofArray(addr.address), 0, msg, (off + 4).toLong(), addrLen.toLong())

        // IFA_ADDRESS
        off += nlaLocalPad
        msg.set(ValueLayout.JAVA_SHORT, off.toLong(), nlaAddrLen.toShort())
        msg.set(ValueLayout.JAVA_SHORT, (off + 2).toLong(), IFA_ADDRESS)
        MemorySegment.copy(MemorySegment.ofArray(addr.address), 0, msg, (off + 4).toLong(), addrLen.toLong())

        if (PosixIO.sendRaw(sock, msg, totalLen.toLong(), 0) < 0) {
            Logger.warn("RTM_NEWADDR send failed: ${Libc.strerror(Libc.errno())}")
            return
        }
        val ack = arena.allocate(256)
        val n = PosixIO.recvRaw(sock, ack, 256, 0)
        if (n >= 20) {
            val err = ack.get(ValueLayout.JAVA_INT, NLMSG_HDRLEN.toLong())
            if (err != 0) {
                Logger.warn("RTM_NEWADDR error: ${Libc.strerror(-err)}")
            }
        }
    }

    /** Set the interface link state to UP via RTM_SETLINK. */
    private fun setLinkUp(arena: Arena, sock: Int, ifindex: Int) {
        val totalLen = NLMSG_HDRLEN + IFINFOMSG_LEN
        val msg = arena.allocate(totalLen.toLong())
        msg.fill(0.toByte())

        msg.set(ValueLayout.JAVA_INT, 0, totalLen)
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_SETLINK)
        msg.set(ValueLayout.JAVA_SHORT, 6, (NLM_F_REQUEST.toInt() or NLM_F_ACK.toInt()).toShort())
        msg.set(ValueLayout.JAVA_INT, 8, 1)

        msg.set(ValueLayout.JAVA_BYTE, NLMSG_HDRLEN.toLong(), 0.toByte())
        msg.set(ValueLayout.JAVA_INT, (NLMSG_HDRLEN + 4).toLong(), ifindex)
        // ifi_flags = IFF_UP, ifi_change = IFF_UP (change only the UP bit)
        msg.set(ValueLayout.JAVA_INT, (NLMSG_HDRLEN + 8).toLong(), Constants.IFF_UP)
        msg.set(ValueLayout.JAVA_INT, (NLMSG_HDRLEN + 12).toLong(), Constants.IFF_UP)

        if (PosixIO.sendRaw(sock, msg, totalLen.toLong(), 0) < 0) {
            Logger.warn("RTM_SETLINK UP send failed: ${Libc.strerror(Libc.errno())}")
            return
        }
        val ack = arena.allocate(256)
        val n = PosixIO.recvRaw(sock, ack, 256, 0)
        if (n >= 20) {
            val err = ack.get(ValueLayout.JAVA_INT, NLMSG_HDRLEN.toLong())
            if (err != 0) {
                Logger.warn("RTM_SETLINK UP error: ${Libc.strerror(-err)}")
            }
        }
    }

    private fun align4(len: Int): Int = (len + 3) and 3.inv()
}
