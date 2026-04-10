package com.dpi.reader;

import com.dpi.model.FiveTuple;
import com.dpi.model.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads a PCAP file and produces {@link Packet} objects.
 *
 * C++ mapping: PcapReader (pcap_reader.h / pcap_reader.cpp)
 *              + packet-building logic from dpi_mt.cpp main loop
 *
 * We implement our own binary reader instead of using Pcap4J's offline handle
 * so that we have full control over byte-order detection and payload-offset
 * calculation — exactly mirroring the C++ implementation.
 *
 * PCAP file format:
 *   Global header  (24 bytes, once)
 *   Per-packet:
 *     Packet header (16 bytes)
 *     Packet data   (incl_len bytes)
 */
public class PcapReader implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(PcapReader.class);

    // Magic numbers
    private static final long MAGIC_LE = 0xa1b2c3d4L; // little-endian file
    private static final long MAGIC_BE = 0xd4c3b2a1L; // big-endian file

    // Protocol constants (mirrors packet_parser.h)
    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;
    private static final int ETHERTYPE_IPV4 = 0x0800;

    // ---- state ----
    private DataInputStream in;
    private ByteOrder       fileOrder;
    private GlobalHeader    globalHeader;
    private int             packetCounter = 0;

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Open a PCAP file for reading.
     * @throws IOException if the file cannot be opened or has an invalid header
     */
    public void open(String path) throws IOException {
        in = new DataInputStream(new BufferedInputStream(new FileInputStream(path)));
        globalHeader = readGlobalHeader();
        log.info("Opened PCAP: version {}.{}, snaplen {}, link-type {}{}",
                globalHeader.versionMajor, globalHeader.versionMinor,
                globalHeader.snaplen, globalHeader.network,
                globalHeader.network == 1 ? " (Ethernet)" : "");
    }

    /**
     * Read the next packet from the file.
     * Parses Ethernet → IPv4 → TCP/UDP layers and calculates the payload offset.
     *
     * @return the next {@link Packet}, or {@code null} at end-of-file
     * @throws IOException on read error
     */
    public Packet readNextPacket() throws IOException {
        // ---- packet header (16 bytes) ----
        byte[] hdrBuf = new byte[16];
        int n = readFully(hdrBuf);
        if (n < 16) return null; // EOF

        ByteBuffer hdr = ByteBuffer.wrap(hdrBuf).order(fileOrder);
        long tsSec   = Integer.toUnsignedLong(hdr.getInt());
        long tsUsec  = Integer.toUnsignedLong(hdr.getInt());
        long inclLen = Integer.toUnsignedLong(hdr.getInt());
        /* origLen = */ hdr.getInt(); // not used

        if (inclLen > 65535) {
            log.warn("Skipping packet with invalid length: {}", inclLen);
            return null;
        }

        // ---- packet data ----
        byte[] data = new byte[(int) inclLen];
        if (readFully(data) < data.length) return null;

        // ---- parse layers ----
        return buildPacket(data, tsSec, tsUsec);
    }

    public GlobalHeader getGlobalHeader() { return globalHeader; }

    @Override
    public void close() throws IOException {
        if (in != null) { in.close(); in = null; }
    }

    // -----------------------------------------------------------------------
    // Global header
    // -----------------------------------------------------------------------

    private GlobalHeader readGlobalHeader() throws IOException {
        byte[] buf = new byte[24];
        if (readFully(buf) < 24) throw new IOException("Truncated PCAP global header");

        // Read magic as little-endian first
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
        long magic = Integer.toUnsignedLong(bb.getInt());

        if (magic == MAGIC_LE) {
            fileOrder = ByteOrder.LITTLE_ENDIAN;
        } else if (magic == MAGIC_BE) {
            fileOrder = ByteOrder.BIG_ENDIAN;
        } else {
            throw new IOException(String.format("Invalid PCAP magic: 0x%08x", magic));
        }

        // Re-parse with correct byte order
        bb = ByteBuffer.wrap(buf).order(fileOrder);
        bb.getInt(); // skip magic

        GlobalHeader gh = new GlobalHeader();
        gh.magic        = magic;
        gh.versionMajor = Short.toUnsignedInt(bb.getShort());
        gh.versionMinor = Short.toUnsignedInt(bb.getShort());
        gh.thiszone     = bb.getInt();
        gh.sigfigs      = Integer.toUnsignedLong(bb.getInt());
        gh.snaplen      = Integer.toUnsignedLong(bb.getInt());
        gh.network      = Integer.toUnsignedLong(bb.getInt());
        gh.fileOrder    = fileOrder;
        return gh;
    }

    // -----------------------------------------------------------------------
    // Packet building  (mirrors dpi_mt.cpp reader loop + packet_parser.cpp)
    // -----------------------------------------------------------------------

    /**
     * Parse raw frame bytes into a {@link Packet}.
     * Returns null if the frame is not an IPv4/TCP/UDP packet.
     *
     * Layer offsets (Ethernet frame):
     *   [0-13]   Ethernet header (14 bytes)
     *   [14-33]  IPv4 header (20+ bytes, IHL field gives exact length)
     *   [34+]    TCP (20+ bytes) or UDP (8 bytes)
     *   [payload_offset+] Application data
     */
    private Packet buildPacket(byte[] data, long tsSec, long tsUsec) {
        if (data.length < 14) return null;

        // ---- Ethernet ----
        int etherType = readUint16BE(data, 12);
        if (etherType != ETHERTYPE_IPV4) return null; // only IPv4

        // ---- IPv4 ----
        if (data.length < 14 + 20) return null;
        int ipStart  = 14;
        int ipVer    = (data[ipStart] >> 4) & 0x0F;
        if (ipVer != 4) return null;

        int ipIhl    = (data[ipStart] & 0x0F) * 4; // header length in bytes
        int protocol = data[ipStart + 9] & 0xFF;
        int srcIp    = readInt32LE(data, ipStart + 12); // stored little-endian per C++ convention
        int dstIp    = readInt32LE(data, ipStart + 16);

        if (protocol != PROTO_TCP && protocol != PROTO_UDP) return null;

        // ---- Transport ----
        int transportStart = ipStart + ipIhl;
        if (data.length < transportStart + 4) return null;

        int srcPort = readUint16BE(data, transportStart);
        int dstPort = readUint16BE(data, transportStart + 2);
        byte tcpFlags = 0;
        int payloadOffset;

        if (protocol == PROTO_TCP) {
            if (data.length < transportStart + 20) return null;
            tcpFlags = data[transportStart + 13];
            int tcpDataOffset = ((data[transportStart + 12] & 0xFF) >> 4) & 0x0F;
            payloadOffset = transportStart + tcpDataOffset * 4;
        } else { // UDP
            payloadOffset = transportStart + 8;
        }

        int payloadLength = Math.max(0, data.length - payloadOffset);

        FiveTuple tuple = new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
        return new Packet(packetCounter++, tsSec, tsUsec,
                tuple, data, payloadOffset, payloadLength, tcpFlags);
    }

    // -----------------------------------------------------------------------
    // Byte-level helpers
    // -----------------------------------------------------------------------

    /** Read big-endian unsigned 16-bit value. */
    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /**
     * Read 4 bytes as a little-endian int.
     * Mirrors the C++ convention where IP addresses are stored as
     * uint32_t in host (little-endian) byte order.
     */
    private static int readInt32LE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    /** Read exactly buf.length bytes; returns bytes actually read. */
    private int readFully(byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) return total;
            total += n;
        }
        return total;
    }

    // -----------------------------------------------------------------------
    // Inner: GlobalHeader
    // -----------------------------------------------------------------------

    /** Mirrors C++ PcapGlobalHeader struct. */
    public static class GlobalHeader {
        public long      magic;
        public int       versionMajor;
        public int       versionMinor;
        public int       thiszone;
        public long      sigfigs;
        public long      snaplen;
        public long      network;
        public ByteOrder fileOrder;
    }
}
