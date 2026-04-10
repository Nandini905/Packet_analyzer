package com.dpi.engine;

import com.dpi.model.AppType;
import com.dpi.model.Flow;
import com.dpi.model.FiveTuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Per-worker-thread flow table.
 *
 * C++ mapping: ConnectionTracker (connection_tracker.h / connection_tracker.cpp)
 *              + per-FP flows_ map in FastPath::run() (dpi_mt.cpp)
 *
 * Each FastPathWorker owns exactly one ConnectionTracker, so NO external
 * synchronisation is needed on this class.
 *
 * Features:
 *   - O(1) flow lookup via HashMap
 *   - Bidirectional flow matching (tries reverse tuple on miss)
 *   - LRU-style eviction when the table is full
 *   - Stale connection cleanup (configurable timeout)
 */
public class ConnectionTracker {

    private static final Logger log = LoggerFactory.getLogger(ConnectionTracker.class);

    private final int    workerId;
    private final int    maxConnections;

    /**
     * LinkedHashMap with access-order = true gives us LRU eviction for free:
     * the eldest entry (least recently accessed) is at the head.
     */
    private final LinkedHashMap<FiveTuple, Flow> table;

    // ---- counters ----
    private long totalSeen       = 0;
    private long classifiedCount = 0;
    private long blockedCount    = 0;

    public ConnectionTracker(int workerId, int maxConnections) {
        this.workerId       = workerId;
        this.maxConnections = maxConnections;
        // accessOrder=true → get() moves entry to tail (most-recently-used)
        this.table = new LinkedHashMap<>(maxConnections, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<FiveTuple, Flow> eldest) {
                return size() > maxConnections;
            }
        };
    }

    public ConnectionTracker(int workerId) {
        this(workerId, 100_000);
    }

    // =========================================================================
    // Core operations
    // =========================================================================

    /**
     * Get an existing flow or create a new one.
     * Mirrors C++ ConnectionTracker::getOrCreateConnection().
     */
    public Flow getOrCreate(FiveTuple tuple) {
        Flow flow = table.get(tuple);
        if (flow != null) return flow;

        // New flow
        flow = new Flow(tuple);
        table.put(tuple, flow);
        totalSeen++;
        return flow;
    }

    /**
     * Look up an existing flow; tries the reverse tuple for bidirectional matching.
     * Returns null if not found.
     * Mirrors C++ ConnectionTracker::getConnection().
     */
    public Flow get(FiveTuple tuple) {
        Flow flow = table.get(tuple);
        if (flow != null) return flow;
        return table.get(tuple.reverse());
    }

    /**
     * Update per-flow counters and last-seen timestamp.
     * Mirrors C++ ConnectionTracker::updateConnection().
     */
    public void update(Flow flow, int packetBytes) {
        if (flow == null) return;
        flow.touch(packetBytes);
    }

    /**
     * Mark a flow as classified (app type + SNI known).
     * Mirrors C++ ConnectionTracker::classifyConnection().
     */
    public void classify(Flow flow, AppType app, String sni) {
        if (flow == null || flow.classified) return;
        flow.appType     = app;
        flow.sni         = (sni != null) ? sni : "";
        flow.classified  = true;
        classifiedCount++;
    }

    /**
     * Mark a flow as blocked; all future packets will be dropped.
     * Mirrors C++ ConnectionTracker::blockConnection().
     */
    public void block(Flow flow) {
        if (flow == null) return;
        flow.blocked = true;
        blockedCount++;
    }

    // =========================================================================
    // TCP state machine  (mirrors FastPathProcessor::updateTCPState())
    // =========================================================================

    private static final int FLAG_SYN = 0x02;
    private static final int FLAG_ACK = 0x10;
    private static final int FLAG_FIN = 0x01;
    private static final int FLAG_RST = 0x04;

    public void updateTCPState(Flow flow, byte flags) {
        if (flow == null) return;
        int f = flags & 0xFF;

        if ((f & FLAG_SYN) != 0) {
            if ((f & FLAG_ACK) != 0) flow.synAckSeen = true;
            else                     flow.synSeen    = true;
        }
        if ((f & FLAG_FIN) != 0) flow.finSeen = true;
        if ((f & FLAG_RST) != 0) flow.blocked = false; // RST closes the flow
    }

    // =========================================================================
    // Maintenance
    // =========================================================================

    /**
     * Remove flows that have been idle longer than {@code timeout}.
     * Mirrors C++ ConnectionTracker::cleanupStale().
     *
     * @return number of flows removed
     */
    public int cleanupStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Flow>> it = table.entrySet().iterator();
        while (it.hasNext()) {
            Flow f = it.next().getValue();
            if (f.lastSeen.isBefore(cutoff)) {
                it.remove();
                removed++;
            }
        }
        if (removed > 0) {
            log.debug("[CT-{}] Cleaned up {} stale flows", workerId, removed);
        }
        return removed;
    }

    public void clear() { table.clear(); }

    // =========================================================================
    // Accessors / reporting
    // =========================================================================

    public int  getActiveCount()    { return table.size(); }
    public long getTotalSeen()      { return totalSeen; }
    public long getClassifiedCount(){ return classifiedCount; }
    public long getBlockedCount()   { return blockedCount; }

    /** Iterate over all flows (for reporting). */
    public void forEach(Consumer<Flow> action) {
        table.values().forEach(action);
    }

    public List<Flow> getAllFlows() {
        return new ArrayList<>(table.values());
    }

    public record TrackerStats(long active, long totalSeen, long classified, long blocked) {}

    public TrackerStats getStats() {
        return new TrackerStats(table.size(), totalSeen, classifiedCount, blockedCount);
    }
}
