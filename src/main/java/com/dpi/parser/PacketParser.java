package com.dpi.parser;

import com.dpi.model.FiveTuple;
import com.dpi.model.Packet;

import java.nio.ByteOrder;

/**
 * Stateless utility class that parses raw Ethernet frames into structured
 * {@link ParsedPacket} objects.
 *
 * C++ mapping: PacketParser (packet_parser.h / packet_parser.cpp)
 *
 * Supported stack: Ethernet II → IPv4 → TCP | UDP
 * All multi-byte protocol fields are big-endian (network byte order).
 */
public final class PacketParser {

    // EtherType constants
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    // IP protocol numbers
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // TCP flag bitmasks
    public static final int FLAG_FIN = 0x01;
    public static final int FLAG_SYN = 0x02;
    public static final int FLAG_RST = 0x04;
    public static final int FLAG_PSH = 0x08;
    public static final int FLAG_ACK = 0x10;
    public static final int FLAG_URG = 0x20;

    private PacketParser() {}

    // -----------------------------------------------------------------------
    // Main parse entry point
    // -----------------------------------------------------------------------

    /**
     * Parse a raw frame byte array into a {@link ParsedPacket}.
     * Returns {@code null} if the frame is too short or not IPv4/TCP/UDP.
     *
     * @param data  raw frame bytes (Ethernet frame)
     * @param tsSec  timestamp seconds
     * @param tsUsec timestamp microseconds
     */
    public static ParsedPacket parse(byte[] data, long tsSec, long tsUsec) {
        if (data == null || data.length < 14) return null;

        ParsedPacket p = new ParsedPacket();
        p.tsSec  = tsSec;
        p.tsUsec = tsUsec;

        // ---- Ethernet (14 bytes) ----
        p.dstMac   = macToString(data, 0);
        p.srcMac   = macToString(data, 6);
        p.etherType = readUint16BE(data, 12);

        if (p.etherType != ETHERTYPE_IPV4) return null; // only IPv4 supported

        // ---- IPv4 ----
        if (data.length < 14 + 20) return null;
        int ipStart = 14;

        int versionIhl = data[ipStart] & 0xFF;
        p.ipVersion = (versionIhl >> 4) & 0x0F;
        if (p.ipVersion != 4) return null;

        int ipHeaderLen = (versionIhl & 0x0F) * 4;
        if (ipHeaderLen < 20 || data.length < ipStart + ipHeaderLen) return null;

        p.ttl      = data[ipStart + 8] & 0xFF;
        p.protocol = data[ipStart + 9] & 0xFF;
        p.srcIp    = ipToString(data, ipStart + 12);
        p.dstIp    = ipToString(data, ipStart + 16);
        p.hasIp    = true;

        int transportStart = ipStart + ipHeaderLen;

        // ---- TCP ----
        if (p.protocol == PROTO_TCP) {
            if (data.length < transportStart + 20) return null;
            p.srcPort   = readUint16BE(data, transportStart);
            p.dstPort   = readUint16BE(data, transportStart + 2);
            p.seqNumber = readUint32BE(data, transportStart + 4);
            p.ackNumber = readUint32BE(data, transportStart + 8);
            int dataOffset = ((data[transportStart + 12] & 0xFF) >> 4) & 0x0F;
            int tcpHeaderLen = dataOffset * 4;
            if (tcpHeaderLen < 20 || data.length < transportStart + tcpHeaderLen) return null;
            p.tcpFlags = (byte)(data[transportStart + 13] & 0xFF);
            p.hasTcp   = true;
            p.payloadOffset = transportStart + tcpHeaderLen;

        // ---- UDP ----
        } else if (p.protocol == PROTO_UDP) {
            if (data.length < transportStart + 8) return null;
            p.srcPort = readUint16BE(data, transportStart);
            p.dstPort = readUint16BE(data, transportStart + 2);
            p.hasUdp  = true;
            p.payloadOffset = transportStart + 8;

        } else {
            return null; // ICMP etc. not processed
        }

        p.payloadLength = Math.max(0, data.length - p.payloadOffset);
        return p;
    }

    // -----------------------------------------------------------------------
    // Formatting helpers
    // -----------------------------------------------------------------------

    public static String macToString(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                data[offset]   & 0xFF, data[offset+1] & 0xFF, data[offset+2] & 0xFF,
                data[offset+3] & 0xFF, data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }

    public static String ipToString(byte[] data, int offset) {
        return (data[offset]   & 0xFF) + "." + (data[offset+1] & 0xFF) + "."
             + (data[offset+2] & 0xFF) + "." + (data[offset+3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP  -> "TCP";
            case PROTO_UDP  -> "UDP";
            default         -> "UNKNOWN(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(byte flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & FLAG_SYN) != 0) sb.append("SYN ");
        if ((flags & FLAG_ACK) != 0) sb.append("ACK ");
        if ((flags & FLAG_FIN) != 0) sb.append("FIN ");
        if ((flags & FLAG_RST) != 0) sb.append("RST ");
        if ((flags & FLAG_PSH) != 0) sb.append("PSH ");
        if ((flags & FLAG_URG) != 0) sb.append("URG ");
        return sb.isEmpty() ? "none" : sb.toString().trim();
    }

    // -----------------------------------------------------------------------
    // Low-level byte readers
    // -----------------------------------------------------------------------

    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    public static long readUint32BE(byte[] data, int offset) {
        return ((long)(data[offset]   & 0xFF) << 24)
             | ((long)(data[offset+1] & 0xFF) << 16)
             | ((long)(data[offset+2] & 0xFF) <<  8)
             |  (long)(data[offset+3] & 0xFF);
    }
}
