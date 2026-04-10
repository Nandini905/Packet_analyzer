package com.dpi.multithreading;

import com.dpi.dpi.DNSExtractor;
import com.dpi.dpi.HTTPHostExtractor;
import com.dpi.dpi.SNIExtractor;
import com.dpi.engine.ConnectionTracker;
import com.dpi.engine.RuleManager;
import com.dpi.engine.Statistics;
import com.dpi.model.AppType;
import com.dpi.model.Flow;
import com.dpi.model.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.LongAdder;

/**
 * Fast Path Worker thread: the DPI workhorse.
 *
 * C++ mapping: class FastPath (dpi_mt.cpp)
 *
 * Each worker:
 *   1. Pops packets from its dedicated input queue
 *   2. Looks up / creates the flow entry (ConnectionTracker)
 *   3. Classifies the flow (SNI, HTTP Host, DNS, port-based)
 *   4. Checks blocking rules (RuleManager)
 *   5. Forwards allowed packets to the output queue
 *   6. Periodically cleans up stale flows
 *
 * Thread-safety:
 *   - Each worker has its OWN ConnectionTracker → no sharing, no locks needed
 *   - RuleManager is shared but internally uses ReadWriteLocks
 *   - Statistics uses LongAdder (lock-free)
 *   - Output queue is a BlockingQueue (thread-safe)
 */
public class FastPathWorker implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(FastPathWorker.class);

    // Cleanup stale flows every N packets processed
    private static final int CLEANUP_INTERVAL = 5_000;

    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;
    private static final int FLAG_SYN  = 0x02;
    private static final int FLAG_ACK  = 0x10;
    private static final int FLAG_FIN  = 0x01;
    private static final int FLAG_RST  = 0x04;

    // ---- identity ----
    private final int workerId;

    // ---- shared (read-only from this thread's perspective) ----
    private final RuleManager  ruleManager;
    private final Statistics   stats;
    private final QueueManager queueManager;

    // ---- owned exclusively by this worker ----
    private final ConnectionTracker connTracker;

    // ---- per-worker stats ----
    private final LongAdder processed = new LongAdder();

    // ---- lifecycle ----
    private volatile boolean running = false;
    private Thread thread;

    public FastPathWorker(int workerId, RuleManager ruleManager,
                          Statistics stats, QueueManager queueManager) {
        this.workerId     = workerId;
        this.ruleManager  = ruleManager;
        this.stats        = stats;
        this.queueManager = queueManager;
        this.connTracker  = new ConnectionTracker(workerId);
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    public void start() {
        running = true;
        thread  = new Thread(this, "FP-" + workerId);
        thread.setDaemon(true);
        thread.start();
        log.info("[FP{}] Started", workerId);
    }

    public void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
            try { thread.join(2_000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        log.info("[FP{}] Stopped (processed {})", workerId, processed.sum());
    }

    // =========================================================================
    // Main loop
    // =========================================================================

    @Override
    public void run() {
        BlockingQueue<Packet> myQueue = queueManager.getFPQueue(workerId);
        long packetsSinceCleanup = 0;

        while (running) {
            try {
                Packet pkt = QueueManager.poll(myQueue, 100);
                if (pkt == null) {
                    // Timeout: good time to clean up stale flows
                    connTracker.cleanupStale(Duration.ofSeconds(300));
                    continue;
                }

                processPacket(pkt);
                processed.increment();

                // Periodic stale-flow cleanup
                if (++packetsSinceCleanup >= CLEANUP_INTERVAL) {
                    connTracker.cleanupStale(Duration.ofSeconds(300));
                    packetsSinceCleanup = 0;
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        // Drain remaining packets after stop signal
        BlockingQueue<Packet> myQueue2 = queueManager.getFPQueue(workerId);
        Packet pkt;
        while ((pkt = myQueue2.poll()) != null) {
            try { processPacket(pkt); processed.increment(); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
    }

    // =========================================================================
    // Per-packet processing  (mirrors FastPath::run() in dpi_mt.cpp)
    // =========================================================================

    private void processPacket(Packet pkt) throws InterruptedException {
        // ---- get or create flow ----
        Flow flow = connTracker.getOrCreate(pkt.tuple);
        connTracker.update(flow, pkt.data.length);

        // ---- TCP state machine ----
        if (pkt.tuple.protocol == PROTO_TCP) {
            connTracker.updateTCPState(flow, pkt.tcpFlags);
        }

        // ---- if already blocked, drop immediately ----
        if (flow.blocked) {
            stats.dropped.increment();
            stats.recordApp(flow.appType, flow.sni);
            return;
        }

        // ---- classify if not yet done ----
        if (!flow.classified) {
            classifyFlow(pkt, flow);
        }

        // ---- check blocking rules ----
        if (!flow.blocked) {
            RuleManager.BlockReason reason = ruleManager.shouldBlock(
                    pkt.tuple.srcIp, pkt.tuple.dstPort, flow.appType, flow.sni);
            if (reason != null) {
                connTracker.block(flow);
                log.info("[FP{}] BLOCKED {} reason={}", workerId, pkt.tuple, reason);
            }
        }

        // ---- record stats ----
        stats.recordApp(flow.appType, flow.sni);

        // ---- forward or drop ----
        if (flow.blocked) {
            stats.dropped.increment();
        } else {
            stats.forwarded.increment();
            queueManager.sendToOutput(pkt);
        }
    }

    // =========================================================================
    // Flow classification  (mirrors FastPath::classifyFlow in dpi_mt.cpp)
    // =========================================================================

    private void classifyFlow(Packet pkt, Flow flow) {
        byte[] data = pkt.data;
        int    off  = pkt.payloadOffset;
        int    len  = pkt.payloadLength;

        if (len <= 0 || off + len > data.length) return;

        // ---- 1. TLS SNI (HTTPS, port 443) ----
        if (pkt.tuple.dstPort == 443 && len > 50) {
            Optional<String> sni = SNIExtractor.extract(data, off, len);
            if (sni.isPresent()) {
                AppType app = AppType.fromSni(sni.get());
                connTracker.classify(flow, app, sni.get());
                log.debug("[FP{}] SNI={} → {}", workerId, sni.get(), app.displayName());
                return;
            }
        }

        // ---- 2. HTTP Host header (port 80) ----
        if (pkt.tuple.dstPort == 80 && len > 10) {
            Optional<String> host = HTTPHostExtractor.extract(data, off, len);
            if (host.isPresent()) {
                AppType app = AppType.fromSni(host.get());
                connTracker.classify(flow, app, host.get());
                log.debug("[FP{}] HTTP Host={} → {}", workerId, host.get(), app.displayName());
                return;
            }
        }

        // ---- 3. DNS (port 53) ----
        if (pkt.tuple.dstPort == 53 || pkt.tuple.srcPort == 53) {
            Optional<String> domain = DNSExtractor.extractQuery(data, off, len);
            connTracker.classify(flow, AppType.DNS, domain.orElse(""));
            return;
        }

        // ---- 4. Port-based fallback (don't mark classified — SNI may arrive later) ----
        if (pkt.tuple.dstPort == 443) flow.appType = AppType.HTTPS;
        else if (pkt.tuple.dstPort == 80) flow.appType = AppType.HTTP;
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    public int               getWorkerId()      { return workerId; }
    public long              getProcessed()     { return processed.sum(); }
    public ConnectionTracker getConnTracker()   { return connTracker; }
}
