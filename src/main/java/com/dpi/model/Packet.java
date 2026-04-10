package com.dpi.model;

/**
 * Self-contained packet wrapper passed between pipeline stages via queues.
 *
 * C++ mapping: struct Packet (dpi_mt.cpp)
 *
 * All data is copied into the byte array at creation time so no raw pointers
 * are needed and the object is safe to hand off to any thread.
 */
public final class Packet {

    public final int      id;
    public final long     tsSec;
    public final long     tsUsec;
    public final FiveTuple tuple;
    public final byte[]   data;          // full raw frame bytes
    public final int      payloadOffset; // byte offset of L7 payload within data[]
    public final int      payloadLength; // number of L7 payload bytes
    public final byte     tcpFlags;      // TCP flags byte (0 for UDP)

    public Packet(int id, long tsSec, long tsUsec,
                  FiveTuple tuple, byte[] data,
                  int payloadOffset, int payloadLength,
                  byte tcpFlags) {
        this.id            = id;
        this.tsSec         = tsSec;
        this.tsUsec        = tsUsec;
        this.tuple         = tuple;
        this.data          = data;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
        this.tcpFlags      = tcpFlags;
    }

    /** Convenience: return a slice of the payload as a new array (for extractors). */
    public byte[] payloadBytes() {
        if (payloadLength <= 0) return new byte[0];
        byte[] out = new byte[payloadLength];
        System.arraycopy(data, payloadOffset, out, 0, payloadLength);
        return out;
    }

    @Override
    public String toString() {
        return "Packet#" + id + "[" + tuple + ", len=" + data.length + "]";
    }
}
