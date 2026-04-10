package com.dpi.model;

import java.time.Instant;

/**
 * Mutable per-flow state entry maintained by ConnectionTracker.
 *
 * C++ mapping: struct FlowEntry (dpi_mt.cpp) + struct Connection (types.h)
 *
 * Each FastPathWorker owns its own flow table so no external synchronisation
 * is needed on this object.
 */
public class Flow {

    // ---- Identity ----
    public final FiveTuple tuple;

    // ---- Classification ----
    public AppType appType  = AppType.UNKNOWN;
    public String  sni      = "";          // Server Name Indication or HTTP Host
    public boolean classified = false;     // true once SNI/Host has been extracted

    // ---- Counters ----
    public long packets = 0;
    public long bytes   = 0;

    // ---- Decision ----
    public boolean blocked = false;

    // ---- TCP state machine ----
    public boolean synSeen    = false;
    public boolean synAckSeen = false;
    public boolean finSeen    = false;

    // ---- Timestamps ----
    public Instant firstSeen = Instant.now();
    public Instant lastSeen  = Instant.now();

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    /** Update counters and last-seen timestamp on every packet. */
    public void touch(int packetBytes) {
        packets++;
        bytes   += packetBytes;
        lastSeen = Instant.now();
    }

    @Override
    public String toString() {
        return "Flow{" + tuple + ", app=" + appType.displayName()
                + (sni.isEmpty() ? "" : ", sni=" + sni)
                + ", pkts=" + packets
                + (blocked ? ", BLOCKED" : "") + "}";
    }
}
