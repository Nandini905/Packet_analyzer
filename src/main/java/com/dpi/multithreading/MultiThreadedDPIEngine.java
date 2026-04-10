package com.dpi.multithreading;

import com.dpi.engine.RuleManager;
import com.dpi.engine.Statistics;
import com.dpi.model.AppType;
import com.dpi.model.Packet;
import com.dpi.reader.PcapReader;
import com.dpi.reader.PcapWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Multi-threaded DPI Engine.
 *
 * C++ mapping: class DPIEngine (dpi_mt.cpp)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ARCHITECTURE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *   Reader Thread
 *       │  hash(5-tuple) % numLBs
 *       ▼
 *   ┌──────┐  ┌──────┐          ← numLBs LoadBalancer threads
 *   │ LB-0 │  │ LB-1 │
 *   └──┬───┘  └──┬───┘
 *      │  hash(5-tuple) % totalFPs
 *      ▼         ▼
 *   ┌────┐ ┌────┐ ┌────┐ ┌────┐ ← totalFPs FastPathWorker threads
 *   │FP-0│ │FP-1│ │FP-2│ │FP-3│
 *   └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘
 *      └──────┴───────┴──────┘
 *                  │
 *                  ▼
 *           Output Queue
 *                  │
 *                  ▼
 *          OutputWriter Thread  → output.pcap
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * KEY DESIGN DECISIONS
 * ─────────────────────────────────────────────────────────────────────────────
 *  • Consistent hashing: same five-tuple always → same FP worker
 *    This is CRITICAL for correct flow tracking (each FP owns its flow table).
 *  • Producer-consumer via ArrayBlockingQueue (bounded, blocking)
 *  • ExecutorService manages thread lifecycle cleanly
 *  • Statistics use LongAdder (lock-free, high throughput)
 * ─────────────────────────────────────────────────────────────────────────────
 */
public class MultiThreadedDPIEngine {

    private static final Logger log = LoggerFactory.getLogger(MultiThreadedDPIEngine.class);

    // =========================================================================
    // Configuration
    // =========================================================================

    public record Config(int numLBs, int fpsPerLB) {
        public Config() { this(2, 2); }
        public int totalFPs() { return numLBs * fpsPerLB; }
    }

    // =========================================================================
    // Fields
    // =========================================================================

    private final Config       config;
    private final RuleManager  ruleManager;
    private final Statistics   stats;
    private final QueueManager queueManager;

    private final List<LoadBalancer>    lbs     = new ArrayList<>();
    private final List<FastPathWorker>  workers = new ArrayList<>();

    private ExecutorService lbExecutor;
    private ExecutorService fpExecutor;
    private ExecutorService outputExecutor;

    private final AtomicBoolean outputRunning = new AtomicBoolean(false);

    // =========================================================================
    // Constructor
    // =========================================================================

    public MultiThreadedDPIEngine(Config config) {
        this.config       = config;
        this.ruleManager  = new RuleManager();
        this.stats        = new Statistics();
        this.queueManager = new QueueManager(config.numLBs(), config.totalFPs());
        printBanner();
    }

    // =========================================================================
    // Rule management API
    // =========================================================================

    public void blockIP(String ip)         { ruleManager.blockIP(ip); }
    public void blockApp(String name)      { ruleManager.blockApp(name); }
    public void blockApp(AppType app)      { ruleManager.blockApp(app); }
    public void blockDomain(String domain) { ruleManager.blockDomain(domain); }
    public void blockPort(int port)        { ruleManager.blockPort(port); }
    public boolean loadRules(String file)  { return ruleManager.loadRules(file); }
    public boolean saveRules(String file)  { return ruleManager.saveRules(file); }

    // =========================================================================
    // Main processing entry point
    // =========================================================================

    /**
     * Process an entire PCAP file using the multi-threaded pipeline.
     *
     * @param inputFile  path to input .pcap
     * @param outputFile path to output .pcap (filtered traffic)
     * @return true on success
     */
    public boolean processFile(String inputFile, String outputFile) {
        log.info("[Engine] Input:  {}", inputFile);
        log.info("[Engine] Output: {}", outputFile);

        try (PcapReader reader = new PcapReader();
             PcapWriter writer = new PcapWriter(outputFile)) {

            reader.open(inputFile);
            writer.writeGlobalHeader(reader.getGlobalHeader());

            // ---- start all worker threads ----
            startWorkers(writer);

            // ---- reader loop (runs on the calling thread) ----
            log.info("[Reader] Processing packets...");
            int packetCount = 0;
            Packet pkt;

            while ((pkt = reader.readNextPacket()) != null) {
                // Update global stats
                stats.totalPackets.increment();
                stats.totalBytes.add(pkt.data.length);
                if (pkt.tuple.protocol == 6)  stats.tcpPackets.increment();
                else if (pkt.tuple.protocol == 17) stats.udpPackets.increment();

                // Route to the correct LB (consistent hash)
                queueManager.routeToLB(pkt);
                packetCount++;
            }

            log.info("[Reader] Finished reading {} packets", packetCount);

            // ---- graceful shutdown ----
            shutdown();

        } catch (IOException | InterruptedException e) {
            log.error("[Engine] Fatal error: {}", e.getMessage());
            return false;
        }

        // ---- final report ----
        printReport();
        log.info("[Engine] Output written to: {}", outputFile);
        return true;
    }

    // =========================================================================
    // Thread management
    // =========================================================================

    private void startWorkers(PcapWriter writer) {
        // ---- FastPath workers ----
        fpExecutor = Executors.newFixedThreadPool(config.totalFPs(),
                r -> { Thread t = new Thread(r); t.setDaemon(true); return t; });

        for (int i = 0; i < config.totalFPs(); i++) {
            FastPathWorker w = new FastPathWorker(i, ruleManager, stats, queueManager);
            workers.add(w);
            w.start();
        }

        // ---- Load balancers ----
        lbExecutor = Executors.newFixedThreadPool(config.numLBs(),
                r -> { Thread t = new Thread(r); t.setDaemon(true); return t; });

        for (int i = 0; i < config.numLBs(); i++) {
            LoadBalancer lb = new LoadBalancer(i, queueManager);
            lbs.add(lb);
            lb.start();
        }

        // ---- Output writer ----
        outputRunning.set(true);
        outputExecutor = Executors.newSingleThreadExecutor(
                r -> { Thread t = new Thread(r, "OutputWriter"); t.setDaemon(true); return t; });
        outputExecutor.submit(() -> outputWriterLoop(writer));

        log.info("[Engine] All threads started ({} LBs, {} FPs)", config.numLBs(), config.totalFPs());
    }

    /**
     * Output writer loop: drains the output queue and writes packets to the PCAP file.
     * Mirrors the output_thread lambda in dpi_mt.cpp.
     */
    private void outputWriterLoop(PcapWriter writer) {
        while (outputRunning.get() || !queueManager.getOutputQueue().isEmpty()) {
            try {
                Packet pkt = QueueManager.poll(queueManager.getOutputQueue(), 100);
                if (pkt == null) continue;
                writer.writePacket(pkt);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (IOException e) {
                log.error("[OutputWriter] Write error: {}", e.getMessage());
            }
        }
        log.debug("[OutputWriter] Finished");
    }

    private void shutdown() throws InterruptedException {
        log.info("[Engine] Shutting down...");

        // 1. Let queues drain (give workers time to process remaining packets)
        Thread.sleep(500);

        // 2. Stop LBs first (they feed FPs)
        lbs.forEach(LoadBalancer::stop);
        lbExecutor.shutdown();
        lbExecutor.awaitTermination(5, TimeUnit.SECONDS);

        // 3. Stop FP workers
        workers.forEach(FastPathWorker::stop);
        fpExecutor.shutdown();
        fpExecutor.awaitTermination(5, TimeUnit.SECONDS);

        // 4. Stop output writer
        outputRunning.set(false);
        outputExecutor.shutdown();
        outputExecutor.awaitTermination(5, TimeUnit.SECONDS);

        log.info("[Engine] All threads stopped");
    }

    // =========================================================================
    // Reporting
    // =========================================================================

    private void printReport() {
        // Build per-worker stats list
        List<Statistics.WorkerStats> workerStatsList = new ArrayList<>();
        for (LoadBalancer lb : lbs) {
            workerStatsList.add(new Statistics.WorkerStats("LB-" + lb.getId(), lb.getDispatched()));
        }
        for (FastPathWorker w : workers) {
            workerStatsList.add(new Statistics.WorkerStats("FP-" + w.getWorkerId(), w.getProcessed()));
        }
        stats.printReport(workerStatsList);
    }

    private void printBanner() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║              DPI ENGINE v2.0 (Java, Multi-threaded)           ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf ("║   Load Balancers:    %3d                                       ║%n", config.numLBs());
        System.out.printf ("║   FPs per LB:        %3d                                       ║%n", config.fpsPerLB());
        System.out.printf ("║   Total FP threads:  %3d                                       ║%n", config.totalFPs());
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }
}
