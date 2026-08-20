package com.ternbusty.takoyaki.process;

import com.ternbusty.takoyaki.logger.Logger;
import com.ternbusty.takoyaki.spec.Spec;
import com.ternbusty.takoyaki.syscall.Constants;
import com.ternbusty.takoyaki.syscall.Libc;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.List;

/**
 * Apply NUMA memory policy via set_mempolicy(2).
 * Called early in the init process, before execve.
 */
public final class MemPolicy {
    private MemPolicy() {}

    // linux/mempolicy.h constants
    private static final int MPOL_DEFAULT    = 0;
    private static final int MPOL_PREFERRED  = 1;
    private static final int MPOL_BIND       = 2;
    private static final int MPOL_INTERLEAVE = 3;
    private static final int MPOL_LOCAL      = 4;

    private static final int MPOL_F_STATIC_NODES   = 1 << 15;
    private static final int MPOL_F_RELATIVE_NODES = 1 << 14;

    /**
     * Validate and apply the memory policy. Throws on invalid config;
     * does nothing when {@code policy} is null.
     */
    public static void apply(Spec.MemoryPolicy policy) {
        if (policy == null) return;

        int mode = parseMode(policy.mode);
        int flags = parseFlags(policy.flags);

        // Parse node bitmask from the "nodes" string (e.g. "0", "0-3", "0,2").
        long[] nodeMask = null;
        int maxNode = 0;
        if (policy.nodes != null && !policy.nodes.isEmpty()) {
            nodeMask = parseNodeMask(policy.nodes);
            maxNode = nodeMask.length * 64;
        }

        // Validate mode-specific constraints
        if (mode == MPOL_DEFAULT && nodeMask != null && maxNode > 0) {
            // MPOL_DEFAULT requires 0 nodes
            long total = 0;
            for (long m : nodeMask) total += Long.bitCount(m);
            if (total > 0) {
                throw new RuntimeException("invalid memory policy: MPOL_DEFAULT "
                        + "mode requires 0 nodes but got " + total);
            }
        }

        int modeWithFlags = mode | flags;

        try (Arena arena = Arena.ofConfined()) {
            long nodemaskAddr = 0;
            if (nodeMask != null && nodeMask.length > 0) {
                MemorySegment seg = arena.allocate(nodeMask.length * 8L);
                for (int i = 0; i < nodeMask.length; i++) {
                    seg.set(ValueLayout.JAVA_LONG, (long) i * 8, nodeMask[i]);
                }
                nodemaskAddr = seg.address();
            }

            long rc = Libc.syscall(Constants.NR_set_mempolicy,
                    modeWithFlags, nodemaskAddr, (long) maxNode, 0L, 0L);
            if (rc != 0) {
                throw new RuntimeException("set_mempolicy failed: "
                        + Libc.strerror(Libc.errno()));
            }
            Logger.debug("set_mempolicy mode=" + mode + " flags=" + flags
                    + " maxnode=" + maxNode);
        }
    }

    private static int parseMode(String mode) {
        if (mode == null || mode.isEmpty()) {
            throw new RuntimeException("invalid memory policy mode: (empty)");
        }
        return switch (mode) {
            case "MPOL_DEFAULT"    -> MPOL_DEFAULT;
            case "MPOL_PREFERRED"  -> MPOL_PREFERRED;
            case "MPOL_BIND"       -> MPOL_BIND;
            case "MPOL_INTERLEAVE" -> MPOL_INTERLEAVE;
            case "MPOL_LOCAL"      -> MPOL_LOCAL;
            default -> throw new RuntimeException(
                    "invalid memory policy mode: " + mode);
        };
    }

    private static int parseFlags(List<String> flags) {
        if (flags == null || flags.isEmpty()) return 0;
        int result = 0;
        for (String f : flags) {
            result |= switch (f) {
                case "MPOL_F_STATIC_NODES"   -> MPOL_F_STATIC_NODES;
                case "MPOL_F_RELATIVE_NODES" -> MPOL_F_RELATIVE_NODES;
                default -> throw new RuntimeException(
                        "invalid memory policy flag: " + f);
            };
        }
        return result;
    }

    /**
     * Parse a Linux CPU-list style string into a bitmask array.
     * Supports individual nodes ("0,2,4") and ranges ("0-3").
     */
    static long[] parseNodeMask(String nodes) {
        long[] mask = new long[16]; // up to 1024 nodes
        for (String part : nodes.split(",")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            int dash = part.indexOf('-');
            if (dash >= 0) {
                long from, to;
                try {
                    from = Long.parseLong(part.substring(0, dash));
                    to = Long.parseLong(part.substring(dash + 1));
                } catch (NumberFormatException e) {
                    throw new RuntimeException("invalid memory policy node: " + part);
                }
                if (from < 0 || to < 0 || to > 8192) {
                    throw new RuntimeException("invalid memory policy node: " + part);
                }
                for (long n = from; n <= to && n < mask.length * 64L; n++) {
                    mask[(int) (n / 64)] |= 1L << (n % 64);
                }
            } else {
                long n;
                try {
                    n = Long.parseLong(part);
                } catch (NumberFormatException e) {
                    throw new RuntimeException("invalid memory policy node: " + part);
                }
                if (n < 0 || n > 8192) {
                    throw new RuntimeException("invalid memory policy node: " + part);
                }
                if (n < mask.length * 64L) {
                    mask[(int) (n / 64)] |= 1L << (n % 64);
                }
            }
        }
        // Trim trailing zero longs
        int last = mask.length - 1;
        while (last > 0 && mask[last] == 0) last--;
        long[] trimmed = new long[last + 1];
        System.arraycopy(mask, 0, trimmed, 0, trimmed.length);
        return trimmed;
    }
}
