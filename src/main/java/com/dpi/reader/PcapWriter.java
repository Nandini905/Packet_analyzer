package com.dpi.reader;

import com.dpi.model.Packet;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes packets to a PCAP file in little-endian format.
 *
 * C++ mapping: the output-writing logic in dpi_mt.cpp (output_thread lambda)
 *
 * Thread-safety: writePacket() is synchronised so the output writer thread
 * is the only caller, but the lock protects against accidental concurrent use.
 */
public class PcapWriter implements Closeable {

    private static final long MAGIC_LE = 0xa1b2c3d4L;

    private final OutputStream out;

    public PcapWriter(String path) throws IOException {
        out = new BufferedOutputStream(new FileOutputStream(path));
    }

    /** Write the 24-byte global header. Must be called exactly once before any packets. */
    public void writeGlobalHeader(PcapReader.GlobalHeader src) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) MAGIC_LE);
        bb.putShort((short) src.versionMajor);
        bb.putShort((short) src.versionMinor);
        bb.putInt(src.thiszone);
        bb.putInt((int) src.sigfigs);
        bb.putInt((int) src.snaplen);
        bb.putInt((int) src.network);
        out.write(bb.array());
    }

    /** Write a single packet (16-byte header + raw data). Thread-safe. */
    public synchronized void writePacket(Packet pkt) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) pkt.tsSec);
        bb.putInt((int) pkt.tsUsec);
        bb.putInt(pkt.data.length);
        bb.putInt(pkt.data.length);
        out.write(bb.array());
        out.write(pkt.data);
    }

    @Override
    public void close() throws IOException {
        out.flush();
        out.close();
    }
}
