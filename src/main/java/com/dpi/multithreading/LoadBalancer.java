package com.dpi.multithreading;

import com.dpi.model.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.LongAdder;

/**
 * Load Balancer thread: reads packets from its own input queue and routes
 * each one to the correct FastPathWorker queue using consistent hashing.
 *
 * C++ mapping: class LoadBalancer (dpi_mt.cpp)
 *
 * Why consistent hashing?
 *   All packets belonging to the same five-tuple (flow) MUST go to the same
 *   FastPathWorker so that the per-worker flow table stays consistent.
 *   hash(FiveTuple) % totalFPs guarantees this.
 *
 * Pipeline position:
 *   Reader → [LB queue] → LoadBalancer → [FP queue] → FastPathWorker
 */
public class LoadBalancer implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(LoadBalancer.class);

    private final int          lbId;
    private final QueueManager queueManager;

    // ---- stats ----
    private final LongAdder received   = new LongAdder();
    private final LongAdder dispatched = new LongAdder();

    // ---- lifecycle ----
    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, QueueManager queueManager) {
        this.lbId         = lbId;
        this.queueManager = queueManager;
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    public void start() {
        running = true;
        thread  = new Thread(this, "LB-" + lbId);
        thread.setDaemon(true);
        thread.start();
        log.info("[LB{}] Started", lbId);
    }

    public void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
            try { thread.join(2_000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        log.info("[LB{}] Stopped (dispatched {})", lbId, dispatched.sum());
    }

    // =========================================================================
    // Main loop
    // =========================================================================

    @Override
    public void run() {
        BlockingQueue<Packet> myQueue = queueManager.getLBQueue(lbId);

        while (running) {
            try {
                // Poll with timeout so we can check the running flag periodically
                Packet pkt = QueueManager.poll(myQueue, 100);
                if (pkt == null) continue;

                received.increment();

                // Route to the correct FP using consistent hash of five-tuple
                queueManager.routeToFP(pkt);
                dispatched.increment();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        // Drain remaining packets after stop signal
        BlockingQueue<Packet> myQueue2 = queueManager.getLBQueue(lbId);
        Packet pkt;
        while ((pkt = myQueue2.poll()) != null) {
            try {
                queueManager.routeToFP(pkt);
                dispatched.increment();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    public int    getId()         { return lbId; }
    public long   getReceived()   { return received.sum(); }
    public long   getDispatched() { return dispatched.sum(); }
}
