package com.dpi.parser;

/**
 * Human-readable parsed representation of a network packet.
 *
 * C++ mapping: struct ParsedPacket (packet_parser.h)
 */
public class ParsedPacket {

    // Timestamps
    public long tsSec;
    public long tsUsec;

    // Ethernet
    public String srcMac;
    public String dstMac;
    public int    etherType;

    // IPv4
    public boolean hasIp      = false;
    public int     ipVersion;
    public String  srcIp;
    public String  dstIp;
    public int     protocol;   // TCP=6, UDP=17
    public int     ttl;

    // Transport
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int     srcPort;
    public int     dstPort;

    // TCP-specific
    public byte tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload
    public int payloadOffset = 0;
    public int payloadLength = 0;

    @Override
    public String toString() {
        return String.format("[%s:%d -> %s:%d %s]",
                srcIp, srcPort, dstIp, dstPort,
                PacketParser.protocolToString(protocol));
    }
}
