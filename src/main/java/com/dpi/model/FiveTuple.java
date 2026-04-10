package com.dpi.model;

import java.util.Objects;

/**
 * Immutable five-tuple that uniquely identifies a network flow (connection).
 *
 * C++ mapping: struct FiveTuple + struct FiveTupleHash in types.h / types.cpp
 *
 * IP addresses are stored as signed Java ints but treated as unsigned 32-bit
 * values everywhere (use Integer.toUnsignedLong() when printing).
 *
 * The hashCode() implementation mirrors the C++ FiveTupleHash so that the
 * same flow always maps to the same worker thread.
 */
public final class FiveTuple {

    public final int srcIp;     // unsigned 32-bit IPv4
    public final int dstIp;     // unsigned 32-bit IPv4
    public final int srcPort;   // unsigned 16-bit
    public final int dstPort;   // unsigned 16-bit
    public final int protocol;  // TCP=6, UDP=17

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort & 0xFFFF;
        this.dstPort  = dstPort & 0xFFFF;
        this.protocol = protocol & 0xFF;
    }

    // -----------------------------------------------------------------------
    // Reverse tuple – used for bidirectional flow matching
    // -----------------------------------------------------------------------
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    // -----------------------------------------------------------------------
    // equals / hashCode
    // -----------------------------------------------------------------------
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp
                && srcPort == t.srcPort && dstPort == t.dstPort
                && protocol == t.protocol;
    }

    /**
     * Hash mirrors the C++ FiveTupleHash (boost-style hash_combine).
     * Critical: same flow MUST always hash to the same worker thread.
     */
    @Override
    public int hashCode() {
        // Use the same XOR-shift combine as the C++ implementation
        long h = 0;
        h = combine(h, Integer.toUnsignedLong(srcIp));
        h = combine(h, Integer.toUnsignedLong(dstIp));
        h = combine(h, srcPort);
        h = combine(h, dstPort);
        h = combine(h, protocol);
        return (int)(h ^ (h >>> 32));
    }

    private static long combine(long h, long v) {
        return h ^ (v + 0x9e3779b9L + (h << 6) + (h >>> 2));
    }

    // -----------------------------------------------------------------------
    // Utility helpers
    // -----------------------------------------------------------------------

    /** Convert a 32-bit IP (little-endian packed int) to dotted-decimal. */
    public static String ipToString(int ip) {
        return (ip & 0xFF) + "."
                + ((ip >> 8) & 0xFF) + "."
                + ((ip >> 16) & 0xFF) + "."
                + ((ip >> 24) & 0xFF);
    }

    /**
     * Parse a dotted-decimal IPv4 string into a 32-bit int stored in
     * the same byte order as the C++ implementation (little-endian packed).
     */
    public static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP: " + ip);
        int result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (Integer.parseInt(parts[i].trim()) & 0xFF) << (i * 8);
        }
        return result;
    }

    @Override
    public String toString() {
        String proto = switch (protocol) {
            case 6  -> "TCP";
            case 17 -> "UDP";
            default -> "PROTO(" + protocol + ")";
        };
        return ipToString(srcIp) + ":" + srcPort
                + " -> " + ipToString(dstIp) + ":" + dstPort
                + " [" + proto + "]";
    }
}
