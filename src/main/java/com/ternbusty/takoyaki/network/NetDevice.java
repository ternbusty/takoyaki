package com.ternbusty.takoyaki.network;

import com.ternbusty.takoyaki.ffi.structs.ifaddrmsg;
import com.ternbusty.takoyaki.ffi.structs.ifinfomsg;
import com.ternbusty.takoyaki.ffi.structs.ifreq;
import com.ternbusty.takoyaki.ffi.structs.nlmsgerr;
import com.ternbusty.takoyaki.ffi.structs.nlmsghdr;
import com.ternbusty.takoyaki.ffi.structs.rtattr;
import com.ternbusty.takoyaki.ffi.structs.sockaddr_nl;
import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;
import com.ternbusty.takoyaki.syscall.PosixIO;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Move network devices into the container's network namespace
 * and optionally rename them, using rtnetlink.
 */
public final class NetDevice {
    private NetDevice() {}

    // Netlink constants
    private static final int AF_NETLINK      = 16;
    private static final int NETLINK_ROUTE   = 0;
    private static final short RTM_SETLINK   = 19;
    private static final short NLM_F_REQUEST = 1;
    private static final short NLM_F_ACK     = 4;
    private static final short IFLA_IFNAME       = 3;
    private static final short IFLA_NET_NS_PID   = 19;

    // RTM_GETADDR / RTM_NEWADDR for address save/restore across netns moves.
    // The kernel strips all IPv4/IPv6 addresses when a device moves between
    // network namespaces. runc preserves permanent global-scope addresses by
    // listing them before the move and re-adding them in the target namespace.
    private static final short RTM_NEWADDR   = 20;
    private static final short RTM_GETADDR   = 22;
    private static final short NLM_F_DUMP    = 0x300;
    private static final short NLM_F_CREATE  = 0x400;
    private static final short NLM_F_EXCL    = 0x200;
    private static final short NLMSG_DONE    = 3;
    private static final short NLMSG_ERROR   = 2;
    private static final short IFA_LOCAL     = 2;
    private static final short IFA_ADDRESS   = 1;
    private static final short IFA_FLAGS     = 8;
    private static final int  IFA_F_PERMANENT = 0x80;
    private static final int  RT_SCOPE_UNIVERSE = 0;

    // ioctl for getting ifindex
    private static final long SIOCGIFINDEX = 0x8933L;

    /** A saved IPv4/IPv6 address to re-add after moving a device. */
    private record SavedAddr(int family, int prefixLen, byte[] address) {}

    /**
     * Move all devices listed in linux.netDevices to the container's net
     * namespace (identified by initPid). Called from the host (MainProcess)
     * after the init process has created its namespaces.
     */
    public static void moveDevices(Map<String, Spec.NetDevice> devices, int initPid) {
        if (devices == null || devices.isEmpty()) return;

        try (Arena arena = Arena.ofConfined()) {
            for (Map.Entry<String, Spec.NetDevice> entry : devices.entrySet()) {
                String hostName = entry.getKey();
                int ifindex = getIfIndex(arena, hostName);
                if (ifindex <= 0) {
                    throw new RuntimeException(
                            "failed to get ifindex for device " + hostName);
                }

                // Save permanent global-scope addresses BEFORE the move.
                // The kernel strips all addresses when a device moves
                // between network namespaces.
                List<SavedAddr> savedAddrs = listPermanentGlobalAddrs(arena, ifindex);

                moveToNamespace(arena, ifindex, initPid);
                Logger.debug("moved " + hostName + " (ifindex=" + ifindex
                        + ") to pid " + initPid + " netns");

                // Re-add saved addresses and bring the interface UP
                // in the container's network namespace. The device still
                // has its original host name at this point (rename happens
                // later inside the container by renameDevices).
                reAddAddressesAndLinkUp(arena, initPid, hostName, savedAddrs);
            }
        }
    }

    /**
     * Rename devices inside the container's network namespace. Called from
     * InitProcess after namespace setup.
     */
    public static void renameDevices(Map<String, Spec.NetDevice> devices) {
        if (devices == null || devices.isEmpty()) return;

        try (Arena arena = Arena.ofConfined()) {
            for (Map.Entry<String, Spec.NetDevice> entry : devices.entrySet()) {
                String hostName = entry.getKey();
                Spec.NetDevice dev = entry.getValue();
                if (dev.name != null && !dev.name.isEmpty() && !dev.name.equals(hostName)) {
                    int ifindex = getIfIndex(arena, hostName);
                    if (ifindex <= 0) {
                        Logger.warn("rename: device " + hostName + " not found");
                        continue;
                    }
                    renameDevice(arena, ifindex, dev.name);
                    Logger.debug("renamed " + hostName + " to " + dev.name);
                }
            }
        }
    }

    /** Look up ifindex for a network interface by name using ioctl. */
    private static int getIfIndex(Arena arena, String name) {
        int sock = PosixIO.socket(Constants.AF_INET, Constants.SOCK_DGRAM, 0);
        if (sock < 0) return -1;
        try {
            MemorySegment req = ifreq.allocate(arena);
            MemorySegment ifrName = ifreq.ifr_ifrn.ifrn_name(ifreq.ifr_ifrn(req));
            byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < Math.min(nameBytes.length, 15); i++) {
                ifrName.set(ValueLayout.JAVA_BYTE, i, nameBytes[i]);
            }
            if (Libc.ioctl(sock, SIOCGIFINDEX, req) != 0) {
                return -1;
            }
            return ifreq.ifr_ifru.ifru_ivalue(ifreq.ifr_ifru(req));
        } finally {
            PosixIO.close(sock);
        }
    }

    /**
     * Move a device to another network namespace via rtnetlink.
     * Sends RTM_SETLINK with IFLA_NET_NS_PID.
     */
    private static void moveToNamespace(Arena arena, int ifindex, int nsPid) {
        int nlaLen = rtaHdrLen() + 4; // rtattr + u32 pid
        int attrOff = nlmsgHdrLen() + align4((int) ifinfomsg.sizeof());
        int totalLen = attrOff + align4(nlaLen);

        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);
        putHeader(msg, totalLen, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);

        MemorySegment ifi = msg.asSlice(nlmsgHdrLen());
        ifinfomsg.ifi_family(ifi, (byte) 0);
        ifinfomsg.ifi_index(ifi, ifindex);

        putAttr(msg, attrOff, nlaLen, IFLA_NET_NS_PID);
        msg.set(ValueLayout.JAVA_INT, attrOff + rtaHdrLen(), nsPid);

        sendNetlink(arena, msg, totalLen);
    }

    /**
     * Rename a device via rtnetlink.
     * Sends RTM_SETLINK with IFLA_IFNAME.
     */
    private static void renameDevice(Arena arena, int ifindex, String newName) {
        byte[] nameBytes = newName.getBytes(StandardCharsets.UTF_8);
        int nlaLen = rtaHdrLen() + nameBytes.length + 1; // rtattr + name + null terminator
        int attrOff = nlmsgHdrLen() + align4((int) ifinfomsg.sizeof());
        int totalLen = attrOff + align4(nlaLen);

        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);
        putHeader(msg, totalLen, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);

        MemorySegment ifi = msg.asSlice(nlmsgHdrLen());
        ifinfomsg.ifi_family(ifi, (byte) 0);
        ifinfomsg.ifi_index(ifi, ifindex);

        putAttr(msg, attrOff, nlaLen, IFLA_IFNAME);
        for (int i = 0; i < nameBytes.length; i++) {
            msg.set(ValueLayout.JAVA_BYTE, attrOff + rtaHdrLen() + i, nameBytes[i]);
        }

        sendNetlink(arena, msg, totalLen);
    }

    /** Open a netlink socket, send the message, read the ACK. */
    private static void sendNetlink(Arena arena, MemorySegment msg, int len) {
        int sock = PosixIO.socket(AF_NETLINK, Constants.SOCK_DGRAM, NETLINK_ROUTE);
        if (sock < 0) {
            throw new RuntimeException("netlink socket: "
                    + Libc.strerror(Libc.errno()));
        }
        try {
            // Bind to kernel (pid=0, groups=0)
            MemorySegment sa = netlinkAddr(arena);
            if (PosixIO.bindRaw(arena, sock, sa, (int) sockaddr_nl.sizeof()) < 0) {
                throw new RuntimeException("netlink bind: "
                        + Libc.strerror(Libc.errno()));
            }

            if (PosixIO.sendRaw(sock, msg, len, 0) < 0) {
                throw new RuntimeException("netlink send: "
                        + Libc.strerror(Libc.errno()));
            }

            // Read ACK (nlmsgerr). The kernel sends back a 36-byte message:
            // nlmsghdr(16) + int error(4) + original nlmsghdr(16)
            MemorySegment ack = arena.allocate(1024);
            long n = PosixIO.recvRaw(sock, ack, 1024, 0);
            if (n < nlmsgHdrLen() + Integer.BYTES) {
                throw new RuntimeException("netlink: no ack received");
            }
            int err = ackError(ack);
            if (err != 0) {
                throw new RuntimeException("netlink: "
                        + Libc.strerror(-err));
            }
        } finally {
            PosixIO.close(sock);
        }
    }

    /**
     * List permanent global-scope addresses on the given interface.
     * Called before a netns move so the addresses can be re-added afterwards.
     */
    private static List<SavedAddr> listPermanentGlobalAddrs(Arena arena, int ifindex) {
        List<SavedAddr> result = new ArrayList<>();
        int sock = PosixIO.socket(AF_NETLINK, Constants.SOCK_DGRAM, NETLINK_ROUTE);
        if (sock < 0) return result;
        try {
            MemorySegment sa = netlinkAddr(arena);
            if (PosixIO.bindRaw(arena, sock, sa, (int) sockaddr_nl.sizeof()) < 0) return result;

            int hdrLen = nlmsgHdrLen();
            int ifaLen = align4((int) ifaddrmsg.sizeof());

            // RTM_GETADDR dump request
            int reqLen = hdrLen + ifaLen;
            MemorySegment req = arena.allocate(reqLen);
            req.fill((byte) 0);
            putHeader(req, reqLen, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
            if (PosixIO.sendRaw(sock, req, reqLen, 0) < 0) return result;

            MemorySegment buf = arena.allocate(65536);
            boolean done = false;
            while (!done) {
                long n = PosixIO.recvRaw(sock, buf, 65536, 0);
                if (n <= 0) break;

                int offset = 0;
                while (offset + hdrLen <= n) {
                    MemorySegment nlh = buf.asSlice(offset);
                    int msgLen = nlmsghdr.nlmsg_len(nlh);
                    if (msgLen < hdrLen || offset + msgLen > n) break;
                    short msgType = nlmsghdr.nlmsg_type(nlh);

                    if (msgType == NLMSG_DONE) { done = true; break; }
                    if (msgType == NLMSG_ERROR) { done = true; break; }

                    if (msgType == RTM_NEWADDR && msgLen >= hdrLen + ifaLen) {
                        MemorySegment ifa = buf.asSlice(offset + hdrLen);
                        int family   = ifaddrmsg.ifa_family(ifa)    & 0xFF;
                        int prefLen  = ifaddrmsg.ifa_prefixlen(ifa) & 0xFF;
                        int ifaFlags = ifaddrmsg.ifa_flags(ifa)     & 0xFF;
                        int scope    = ifaddrmsg.ifa_scope(ifa)     & 0xFF;
                        int index    = ifaddrmsg.ifa_index(ifa);

                        if (index == ifindex && scope == RT_SCOPE_UNIVERSE) {
                            byte[] addrBytes = null;
                            int extFlags = ifaFlags;
                            int attrOff = offset + hdrLen + ifaLen;
                            int attrEnd = offset + align4(msgLen);

                            while (attrOff + rtaHdrLen() <= attrEnd) {
                                MemorySegment rta = buf.asSlice(attrOff);
                                int rtaLen  = rtattr.rta_len(rta)  & 0xFFFF;
                                int rtaType = rtattr.rta_type(rta) & 0xFFFF;
                                if (rtaLen < rtaHdrLen()) break;
                                int dataOff = attrOff + rtaHdrLen();
                                int dataLen = rtaLen - rtaHdrLen();
                                if (rtaType == IFA_LOCAL
                                        || (rtaType == IFA_ADDRESS && addrBytes == null)) {
                                    addrBytes = new byte[dataLen];
                                    MemorySegment.copy(buf, dataOff,
                                            MemorySegment.ofArray(addrBytes), 0, dataLen);
                                } else if (rtaType == IFA_FLAGS && dataLen >= 4) {
                                    extFlags = buf.get(ValueLayout.JAVA_INT, dataOff);
                                }
                                attrOff += align4(rtaLen);
                            }

                            if (addrBytes != null && (extFlags & IFA_F_PERMANENT) != 0) {
                                result.add(new SavedAddr(family, prefLen, addrBytes));
                                Logger.debug("saved addr on ifindex " + ifindex
                                        + " family=" + family + " /" + prefLen);
                            }
                        }
                    }
                    offset += align4(msgLen);
                }
            }
        } finally {
            PosixIO.close(sock);
        }
        return result;
    }

    /**
     * Re-add saved addresses and bring the interface UP in the container's
     * network namespace. Creates a netlink socket inside the target namespace
     * via a temporary setns call, then operates through that socket from the
     * host namespace.
     */
    private static void reAddAddressesAndLinkUp(Arena arena, int initPid,
                                                 String deviceName,
                                                 List<SavedAddr> savedAddrs) {
        // Open namespace fds for the host and the container.
        int hostNsFd = PosixIO.open(arena, "/proc/self/ns/net", Constants.O_RDONLY, 0);
        if (hostNsFd < 0) {
            Logger.warn("cannot open host netns: " + Libc.strerror(Libc.errno()));
            return;
        }
        int containerNsFd = PosixIO.open(arena,
                "/proc/" + initPid + "/ns/net", Constants.O_RDONLY, 0);
        if (containerNsFd < 0) {
            Logger.warn("cannot open container netns for pid " + initPid);
            PosixIO.close(hostNsFd);
            return;
        }

        // Enter the container's netns, create sockets there, then return.
        if (Libc.setns(containerNsFd, Constants.CLONE_NEWNET) != 0) {
            Logger.warn("setns to container netns failed: " + Libc.strerror(Libc.errno()));
            PosixIO.close(hostNsFd);
            PosixIO.close(containerNsFd);
            return;
        }
        int nlSock = PosixIO.socket(AF_NETLINK, Constants.SOCK_DGRAM, NETLINK_ROUTE);
        int newIfindex = getIfIndex(arena, deviceName);
        // Restore the host netns immediately.
        Libc.setns(hostNsFd, Constants.CLONE_NEWNET);
        PosixIO.close(hostNsFd);
        PosixIO.close(containerNsFd);

        if (nlSock < 0 || newIfindex <= 0) {
            Logger.warn("failed to create netlink socket or find " + deviceName
                    + " in container netns");
            if (nlSock >= 0) PosixIO.close(nlSock);
            return;
        }

        try {
            // Bind the netlink socket (created in container's netns).
            MemorySegment sa = netlinkAddr(arena);
            if (PosixIO.bindRaw(arena, nlSock, sa, (int) sockaddr_nl.sizeof()) < 0) {
                Logger.warn("netlink bind in container ns failed");
                return;
            }

            // Re-add each saved address.
            for (SavedAddr addr : savedAddrs) {
                addAddress(arena, nlSock, newIfindex, addr);
            }

            // Bring the interface UP.
            setLinkUp(arena, nlSock, newIfindex);
        } finally {
            PosixIO.close(nlSock);
        }
    }

    /** Send RTM_NEWADDR to add an address to the interface. */
    private static void addAddress(Arena arena, int sock, int ifindex, SavedAddr addr) {
        int addrLen = addr.address.length;
        int nlaLen = rtaHdrLen() + addrLen;
        int nlaPad = align4(nlaLen);
        int base = nlmsgHdrLen();
        int off = base + align4((int) ifaddrmsg.sizeof());
        int totalLen = off + 2 * nlaPad; // IFA_LOCAL + IFA_ADDRESS

        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);
        putHeader(msg, totalLen, RTM_NEWADDR,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);

        MemorySegment ifa = msg.asSlice(base);
        ifaddrmsg.ifa_family(ifa, (byte) addr.family);
        ifaddrmsg.ifa_prefixlen(ifa, (byte) addr.prefixLen);
        ifaddrmsg.ifa_flags(ifa, (byte) 0);
        ifaddrmsg.ifa_scope(ifa, (byte) RT_SCOPE_UNIVERSE);
        ifaddrmsg.ifa_index(ifa, ifindex);

        // IFA_LOCAL
        putAttr(msg, off, nlaLen, IFA_LOCAL);
        MemorySegment.copy(MemorySegment.ofArray(addr.address), 0, msg, off + rtaHdrLen(), addrLen);

        // IFA_ADDRESS
        off += nlaPad;
        putAttr(msg, off, nlaLen, IFA_ADDRESS);
        MemorySegment.copy(MemorySegment.ofArray(addr.address), 0, msg, off + rtaHdrLen(), addrLen);

        if (PosixIO.sendRaw(sock, msg, totalLen, 0) < 0) {
            Logger.warn("RTM_NEWADDR send failed: " + Libc.strerror(Libc.errno()));
            return;
        }
        MemorySegment ack = arena.allocate(256);
        long n = PosixIO.recvRaw(sock, ack, 256, 0);
        if (n >= nlmsgHdrLen() + Integer.BYTES) {
            int err = ackError(ack);
            if (err != 0) {
                Logger.warn("RTM_NEWADDR error: " + Libc.strerror(-err));
            }
        }
    }

    /** Set the interface link state to UP via RTM_SETLINK. */
    private static void setLinkUp(Arena arena, int sock, int ifindex) {
        int totalLen = nlmsgHdrLen() + align4((int) ifinfomsg.sizeof());
        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);
        putHeader(msg, totalLen, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);

        MemorySegment ifi = msg.asSlice(nlmsgHdrLen());
        ifinfomsg.ifi_family(ifi, (byte) 0);
        ifinfomsg.ifi_index(ifi, ifindex);
        // ifi_flags = IFF_UP, ifi_change = IFF_UP (change only the UP bit)
        ifinfomsg.ifi_flags(ifi, Constants.IFF_UP);
        ifinfomsg.ifi_change(ifi, Constants.IFF_UP);

        if (PosixIO.sendRaw(sock, msg, totalLen, 0) < 0) {
            Logger.warn("RTM_SETLINK UP send failed: " + Libc.strerror(Libc.errno()));
            return;
        }
        MemorySegment ack = arena.allocate(256);
        long n = PosixIO.recvRaw(sock, ack, 256, 0);
        if (n >= nlmsgHdrLen() + Integer.BYTES) {
            int err = ackError(ack);
            if (err != 0) {
                Logger.warn("RTM_SETLINK UP error: " + Libc.strerror(-err));
            }
        }
    }

    /** NLMSG_HDRLEN: the nlmsghdr size rounded up to NLMSG_ALIGNTO (4). */
    private static int nlmsgHdrLen() {
        return align4((int) nlmsghdr.sizeof());
    }

    /** RTA_LENGTH(0): the rtattr header size rounded up to RTA_ALIGNTO (4). */
    private static int rtaHdrLen() {
        return align4((int) rtattr.sizeof());
    }

    /** Fill the nlmsghdr at the start of msg; the kernel is the peer (pid 0). */
    private static void putHeader(MemorySegment msg, int len, short type, int flags) {
        nlmsghdr.nlmsg_len(msg, len);
        nlmsghdr.nlmsg_type(msg, type);
        nlmsghdr.nlmsg_flags(msg, (short) flags);
        nlmsghdr.nlmsg_seq(msg, 1);
        nlmsghdr.nlmsg_pid(msg, 0);
    }

    /** Write an rtattr header at off; its payload starts at off + rtaHdrLen(). */
    private static void putAttr(MemorySegment msg, long off, int len, short type) {
        MemorySegment rta = msg.asSlice(off);
        rtattr.rta_len(rta, (short) len);
        rtattr.rta_type(rta, type);
    }

    /** The error field of the nlmsgerr that follows the nlmsghdr of an ACK. */
    private static int ackError(MemorySegment ack) {
        return nlmsgerr.error(ack.asSlice(nlmsgHdrLen()));
    }

    /** sockaddr_nl addressing the kernel (pid 0, no multicast groups). */
    private static MemorySegment netlinkAddr(Arena arena) {
        MemorySegment sa = sockaddr_nl.allocate(arena);
        sockaddr_nl.nl_family(sa, (short) AF_NETLINK);
        return sa;
    }

    private static int align4(int len) {
        return (len + 3) & ~3;
    }
}
