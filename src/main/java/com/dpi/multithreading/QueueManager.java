package com.dpi.multithreading;

import com.dpi.model.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Central queue registry for the multi-threaded pipeline.
 *
 * C++ mapping: TSQueue<Packet> instances in dpi_mt.cpp
 *
 * Pipeline topology:
 *
 *   Reader Thread
 *       │
 *       ▼  (hash % numLBs)
 *   LB queues[0..numLBs-1]   ← one ArrayBlockingQueue per LoadBalancer
 *       │
 *       ▼  (hash % fpsPerLB)
 *   FP queues[0..totalFPs-1] ← one ArrayBlockingQueue per FastPathWorker
 *       │
 *       ▼
 *   Output queue              ← single queue → OutputWriter thread
 *
 * Using Java's ArrayBlockingQueue gives us:
 *   - Bounded capacity (back-pressure)
 *   - Blocking put/poll (no busy-wait)
 *   - Thread-safe without extra locking
 */
public class QueueManager {

    private static final Logger log = LoggerFactory.getLogger(QueueManager.class);

    private static final int LB_QUEUE_CAPACITY  = 10_000;
    private static final int FP_QUEUE_CAPACITY  = 10_000;
    private static final int OUT_QUEUE_CAPACITY = 10_000;

    private final int numLBs;
    private final int totalFPs;

    /** One input queue per LoadBalancer thread. */
    private final List<BlockingQueue<Packet>> lbQueues;

    /** One input queue per FastPathWorker thread. */
    private final List<BlockingQueue<Packet>> fpQueues;

    /** Single output queue consumed by the OutputWriter thread. */
    private final BlockingQueue<Packet> outputQueue;

    public QueueManager(int numLBs, int totalFPs) {
        this.numLBs   = numLBs;
        this.totalFPs = totalFPs;

        lbQueues = new ArrayList<>(numLBs);
        for (int i = 0; i < numLBs; i++) {
            lbQueues.add(new ArrayBlockingQueue<>(LB_QUEUE_CAPACITY));
        }

        fpQueues = new ArrayList<>(totalFPs);
        for (int i = 0; i < totalFPs; i++) {
            fpQueues.add(new ArrayBlockingQueue<>(FP_QUEUE_CAPACITY));
        }

        outputQueue = new ArrayBlockingQueue<>(OUT_QUEUE_CAPACITY);

        log.debug("[QueueManager] Created {} LB queues, {} FP queues, 1 output queue",
                numLBs, totalFPs);
    }

    // =========================================================================
    // Routing helpers
    // =========================================================================

    /**
     * Route a packet to the correct LB queue using the five-tuple hash.
     * Consistent hashing ensures the same flow always goes to the same LB.
     */
    public void routeToLB(Packet pkt) throws InterruptedException {
        int lbIdx = Math.abs(pkt.tuple.hashCode()) % numLBs;
        lbQueues.get(lbIdx).put(pkt);
    }

    /**
     * Route a packet to the correct FP queue.
     * Called by LoadBalancer threads.
     */
    public void routeToFP(Packet pkt) throws InterruptedException {
        int fpIdx = Math.abs(pkt.tuple.hashCode()) % totalFPs;
        fpQueues.get(fpIdx).put(pkt);
    }

    /**
     * Push a forwarded packet to the output queue.
     * Called by FastPathWorker threads.
     */
    public void sendToOutput(Packet pkt) throws InterruptedException {
        outputQueue.put(pkt);
    }

    // =========================================================================
    // Queue accessors
    // =========================================================================

    public BlockingQueue<Packet> getLBQueue(int lbId)  { return lbQueues.get(lbId); }
    public BlockingQueue<Packet> getFPQueue(int fpId)  { return fpQueues.get(fpId); }
    public BlockingQueue<Packet> getOutputQueue()      { return outputQueue; }

    public int getNumLBs()   { return numLBs; }
    public int getTotalFPs() { return totalFPs; }

    // =========================================================================
    // Drain helper (used during shutdown)
    // =========================================================================

    /** Poll with timeout — returns null on timeout. */
    public static Packet poll(BlockingQueue<Packet> queue, long timeoutMs)
            throws InterruptedException {
        return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
    }
}
