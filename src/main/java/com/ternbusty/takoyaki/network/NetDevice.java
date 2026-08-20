package com.ternbusty.takoyaki.network;

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
    private static final int  IFADDRMSG_LEN  = 8;

    // ioctl for getting ifindex
    private static final long SIOCGIFINDEX = 0x8933L;

    // struct nlmsghdr size = 16, struct ifinfomsg size = 16
    private static final int NLMSG_HDRLEN    = 16;
    private static final int IFINFOMSG_LEN   = 16;

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
            // struct ifreq: 16 bytes name + 4 bytes ifindex + padding = 40 bytes
            MemorySegment ifreq = arena.allocate(40);
            ifreq.fill((byte) 0);
            byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < Math.min(nameBytes.length, 15); i++) {
                ifreq.set(ValueLayout.JAVA_BYTE, i, nameBytes[i]);
            }
            if (Libc.ioctl(sock, SIOCGIFINDEX, ifreq) != 0) {
                return -1;
            }
            return ifreq.get(ValueLayout.JAVA_INT, 16);
        } finally {
            PosixIO.close(sock);
        }
    }

    /**
     * Move a device to another network namespace via rtnetlink.
     * Sends RTM_SETLINK with IFLA_NET_NS_PID.
     */
    private static void moveToNamespace(Arena arena, int ifindex, int nsPid) {
        // NLA for IFLA_NET_NS_PID: rta_len=8 (4 header + 4 data), rta_type=IFLA_NET_NS_PID
        int nlaLen = 4 + 4; // rta header + u32
        int nlaPadded = align4(nlaLen);
        int totalLen = NLMSG_HDRLEN + IFINFOMSG_LEN + nlaPadded;

        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);

        // nlmsghdr
        msg.set(ValueLayout.JAVA_INT, 0, totalLen);                             // nlmsg_len
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_SETLINK);                       // nlmsg_type
        msg.set(ValueLayout.JAVA_SHORT, 6, (short)(NLM_F_REQUEST | NLM_F_ACK));// nlmsg_flags
        msg.set(ValueLayout.JAVA_INT, 8, 1);                                   // nlmsg_seq
        msg.set(ValueLayout.JAVA_INT, 12, 0);                                  // nlmsg_pid

        // ifinfomsg
        msg.set(ValueLayout.JAVA_BYTE, NLMSG_HDRLEN, (byte) 0);               // ifi_family
        msg.set(ValueLayout.JAVA_INT, NLMSG_HDRLEN + 4, ifindex);              // ifi_index

        // rtattr IFLA_NET_NS_PID
        int attrOff = NLMSG_HDRLEN + IFINFOMSG_LEN;
        msg.set(ValueLayout.JAVA_SHORT, attrOff, (short) nlaLen);              // rta_len
        msg.set(ValueLayout.JAVA_SHORT, attrOff + 2, IFLA_NET_NS_PID);        // rta_type
        msg.set(ValueLayout.JAVA_INT, attrOff + 4, nsPid);                     // pid value

        sendNetlink(arena, msg, totalLen);
    }

    /**
     * Rename a device via rtnetlink.
     * Sends RTM_SETLINK with IFLA_IFNAME.
     */
    private static void renameDevice(Arena arena, int ifindex, String newName) {
        byte[] nameBytes = newName.getBytes(StandardCharsets.UTF_8);
        int nlaLen = 4 + nameBytes.length + 1; // rta header + name + null terminator
        int nlaPadded = align4(nlaLen);
        int totalLen = NLMSG_HDRLEN + IFINFOMSG_LEN + nlaPadded;

        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);

        // nlmsghdr
        msg.set(ValueLayout.JAVA_INT, 0, totalLen);
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_SETLINK);
        msg.set(ValueLayout.JAVA_SHORT, 6, (short)(NLM_F_REQUEST | NLM_F_ACK));
        msg.set(ValueLayout.JAVA_INT, 8, 1);
        msg.set(ValueLayout.JAVA_INT, 12, 0);

        // ifinfomsg
        msg.set(ValueLayout.JAVA_BYTE, NLMSG_HDRLEN, (byte) 0);
        msg.set(ValueLayout.JAVA_INT, NLMSG_HDRLEN + 4, ifindex);

        // rtattr IFLA_IFNAME
        int attrOff = NLMSG_HDRLEN + IFINFOMSG_LEN;
        msg.set(ValueLayout.JAVA_SHORT, attrOff, (short) nlaLen);
        msg.set(ValueLayout.JAVA_SHORT, attrOff + 2, IFLA_IFNAME);
        for (int i = 0; i < nameBytes.length; i++) {
            msg.set(ValueLayout.JAVA_BYTE, attrOff + 4 + i, nameBytes[i]);
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
            // struct sockaddr_nl = { sa_family (2) + pad (2) + pid (4) + groups (4) } = 12
            MemorySegment sa = arena.allocate(12);
            sa.fill((byte) 0);
            sa.set(ValueLayout.JAVA_SHORT, 0, (short) AF_NETLINK);
            if (PosixIO.bindRaw(arena, sock, sa, 12) < 0) {
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
            if (n < 20) {
                throw new RuntimeException("netlink: no ack received");
            }
            int err = ack.get(ValueLayout.JAVA_INT, NLMSG_HDRLEN);
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
            MemorySegment sa = arena.allocate(12);
            sa.fill((byte) 0);
            sa.set(ValueLayout.JAVA_SHORT, 0, (short) AF_NETLINK);
            if (PosixIO.bindRaw(arena, sock, sa, 12) < 0) return result;

            // RTM_GETADDR dump request
            int reqLen = NLMSG_HDRLEN + IFADDRMSG_LEN;
            MemorySegment req = arena.allocate(reqLen);
            req.fill((byte) 0);
            req.set(ValueLayout.JAVA_INT, 0, reqLen);
            req.set(ValueLayout.JAVA_SHORT, 4, RTM_GETADDR);
            req.set(ValueLayout.JAVA_SHORT, 6, (short) (NLM_F_REQUEST | NLM_F_DUMP));
            req.set(ValueLayout.JAVA_INT, 8, 1);
            if (PosixIO.sendRaw(sock, req, reqLen, 0) < 0) return result;

            MemorySegment buf = arena.allocate(65536);
            boolean done = false;
            while (!done) {
                long n = PosixIO.recvRaw(sock, buf, 65536, 0);
                if (n <= 0) break;

                int offset = 0;
                while (offset + NLMSG_HDRLEN <= n) {
                    int msgLen = buf.get(ValueLayout.JAVA_INT, offset);
                    if (msgLen < NLMSG_HDRLEN || offset + msgLen > n) break;
                    short msgType = buf.get(ValueLayout.JAVA_SHORT, offset + 4);

                    if (msgType == NLMSG_DONE) { done = true; break; }
                    if (msgType == NLMSG_ERROR) { done = true; break; }

                    if (msgType == RTM_NEWADDR
                            && msgLen >= NLMSG_HDRLEN + IFADDRMSG_LEN) {
                        int base = offset + NLMSG_HDRLEN;
                        int family   = buf.get(ValueLayout.JAVA_BYTE, base)     & 0xFF;
                        int prefLen  = buf.get(ValueLayout.JAVA_BYTE, base + 1) & 0xFF;
                        int ifaFlags = buf.get(ValueLayout.JAVA_BYTE, base + 2) & 0xFF;
                        int scope    = buf.get(ValueLayout.JAVA_BYTE, base + 3) & 0xFF;
                        int index    = buf.get(ValueLayout.JAVA_INT,  base + 4);

                        if (index == ifindex && scope == RT_SCOPE_UNIVERSE) {
                            byte[] addrBytes = null;
                            int extFlags = ifaFlags;
                            int attrOff = base + IFADDRMSG_LEN;
                            int attrEnd = offset + align4(msgLen);

                            while (attrOff + 4 <= attrEnd) {
                                int rtaLen  = buf.get(ValueLayout.JAVA_SHORT, attrOff)     & 0xFFFF;
                                int rtaType = buf.get(ValueLayout.JAVA_SHORT, attrOff + 2) & 0xFFFF;
                                if (rtaLen < 4) break;
                                int dataLen = rtaLen - 4;
                                if (rtaType == IFA_LOCAL
                                        || (rtaType == IFA_ADDRESS && addrBytes == null)) {
                                    addrBytes = new byte[dataLen];
                                    MemorySegment.copy(buf, attrOff + 4,
                                            MemorySegment.ofArray(addrBytes), 0, dataLen);
                                } else if (rtaType == IFA_FLAGS && dataLen >= 4) {
                                    extFlags = buf.get(ValueLayout.JAVA_INT, attrOff + 4);
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
            MemorySegment sa = arena.allocate(12);
            sa.fill((byte) 0);
            sa.set(ValueLayout.JAVA_SHORT, 0, (short) AF_NETLINK);
            if (PosixIO.bindRaw(arena, nlSock, sa, 12) < 0) {
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
        int nlaLocalLen = 4 + addrLen;
        int nlaLocalPad = align4(nlaLocalLen);
        int nlaAddrLen = 4 + addrLen;
        int nlaAddrPad = align4(nlaAddrLen);
        int totalLen = NLMSG_HDRLEN + IFADDRMSG_LEN + nlaLocalPad + nlaAddrPad;

        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);

        // nlmsghdr
        msg.set(ValueLayout.JAVA_INT, 0, totalLen);
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_NEWADDR);
        msg.set(ValueLayout.JAVA_SHORT, 6,
                (short) (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
        msg.set(ValueLayout.JAVA_INT, 8, 1);

        // ifaddrmsg
        int base = NLMSG_HDRLEN;
        msg.set(ValueLayout.JAVA_BYTE, base,     (byte) addr.family);
        msg.set(ValueLayout.JAVA_BYTE, base + 1, (byte) addr.prefixLen);
        msg.set(ValueLayout.JAVA_BYTE, base + 2, (byte) 0);           // flags
        msg.set(ValueLayout.JAVA_BYTE, base + 3, (byte) RT_SCOPE_UNIVERSE);
        msg.set(ValueLayout.JAVA_INT,  base + 4, ifindex);

        // IFA_LOCAL
        int off = NLMSG_HDRLEN + IFADDRMSG_LEN;
        msg.set(ValueLayout.JAVA_SHORT, off,     (short) nlaLocalLen);
        msg.set(ValueLayout.JAVA_SHORT, off + 2, IFA_LOCAL);
        MemorySegment.copy(MemorySegment.ofArray(addr.address), 0, msg, off + 4, addrLen);

        // IFA_ADDRESS
        off += nlaLocalPad;
        msg.set(ValueLayout.JAVA_SHORT, off,     (short) nlaAddrLen);
        msg.set(ValueLayout.JAVA_SHORT, off + 2, IFA_ADDRESS);
        MemorySegment.copy(MemorySegment.ofArray(addr.address), 0, msg, off + 4, addrLen);

        if (PosixIO.sendRaw(sock, msg, totalLen, 0) < 0) {
            Logger.warn("RTM_NEWADDR send failed: " + Libc.strerror(Libc.errno()));
            return;
        }
        MemorySegment ack = arena.allocate(256);
        long n = PosixIO.recvRaw(sock, ack, 256, 0);
        if (n >= 20) {
            int err = ack.get(ValueLayout.JAVA_INT, NLMSG_HDRLEN);
            if (err != 0) {
                Logger.warn("RTM_NEWADDR error: " + Libc.strerror(-err));
            }
        }
    }

    /** Set the interface link state to UP via RTM_SETLINK. */
    private static void setLinkUp(Arena arena, int sock, int ifindex) {
        int totalLen = NLMSG_HDRLEN + IFINFOMSG_LEN;
        MemorySegment msg = arena.allocate(totalLen);
        msg.fill((byte) 0);

        msg.set(ValueLayout.JAVA_INT, 0, totalLen);
        msg.set(ValueLayout.JAVA_SHORT, 4, RTM_SETLINK);
        msg.set(ValueLayout.JAVA_SHORT, 6, (short) (NLM_F_REQUEST | NLM_F_ACK));
        msg.set(ValueLayout.JAVA_INT, 8, 1);

        msg.set(ValueLayout.JAVA_BYTE, NLMSG_HDRLEN, (byte) 0);
        msg.set(ValueLayout.JAVA_INT, NLMSG_HDRLEN + 4, ifindex);
        // ifi_flags = IFF_UP, ifi_change = IFF_UP (change only the UP bit)
        msg.set(ValueLayout.JAVA_INT, NLMSG_HDRLEN + 8, Constants.IFF_UP);
        msg.set(ValueLayout.JAVA_INT, NLMSG_HDRLEN + 12, Constants.IFF_UP);

        if (PosixIO.sendRaw(sock, msg, totalLen, 0) < 0) {
            Logger.warn("RTM_SETLINK UP send failed: " + Libc.strerror(Libc.errno()));
            return;
        }
        MemorySegment ack = arena.allocate(256);
        long n = PosixIO.recvRaw(sock, ack, 256, 0);
        if (n >= 20) {
            int err = ack.get(ValueLayout.JAVA_INT, NLMSG_HDRLEN);
            if (err != 0) {
                Logger.warn("RTM_SETLINK UP error: " + Libc.strerror(-err));
            }
        }
    }

    private static int align4(int len) {
        return (len + 3) & ~3;
    }
}
