package com.dpi.engine;

import com.dpi.model.AppType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

/**
 * Global, thread-safe statistics collector.
 *
 * C++ mapping: struct Stats (dpi_mt.cpp)
 *
 * Uses LongAdder for high-throughput concurrent increments (better than
 * AtomicLong under contention because each thread has its own cell).
 * Per-app counts use ConcurrentHashMap with merge().
 */
public class Statistics {

    private static final Logger log = LoggerFactory.getLogger(Statistics.class);

    // ---- packet counters ----
    public final LongAdder totalPackets  = new LongAdder();
    public final LongAdder totalBytes    = new LongAdder();
    public final LongAdder forwarded     = new LongAdder();
    public final LongAdder dropped       = new LongAdder();
    public final LongAdder tcpPackets    = new LongAdder();
    public final LongAdder udpPackets    = new LongAdder();

    // ---- per-app breakdown ----
    private final ConcurrentHashMap<AppType, LongAdder> appCounts = new ConcurrentHashMap<>();

    // ---- detected SNIs (sni → app) ----
    private final ConcurrentHashMap<String, AppType> detectedSnis = new ConcurrentHashMap<>();

    // =========================================================================
    // Recording
    // =========================================================================

    public void recordApp(AppType app, String sni) {
        appCounts.computeIfAbsent(app, k -> new LongAdder()).increment();
        if (sni != null && !sni.isBlank()) {
            detectedSnis.put(sni, app);
        }
    }

    // =========================================================================
    // Reporting
    // =========================================================================

    /**
     * Print a formatted statistics report to stdout.
     * Mirrors C++ DPIEngine::printReport() / generateReport().
     */
    public void printReport(List<WorkerStats> workerStats) {
        long total     = totalPackets.sum();
        long fwd       = forwarded.sum();
        long drp       = dropped.sum();
        double dropPct = total > 0 ? 100.0 * drp / total : 0;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf ("║ Total Packets:      %12d                           ║%n", total);
        System.out.printf ("║ Total Bytes:        %12d                           ║%n", totalBytes.sum());
        System.out.printf ("║ TCP Packets:        %12d                           ║%n", tcpPackets.sum());
        System.out.printf ("║ UDP Packets:        %12d                           ║%n", udpPackets.sum());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf ("║ Forwarded:          %12d                           ║%n", fwd);
        System.out.printf ("║ Dropped/Blocked:    %12d                           ║%n", drp);
        System.out.printf ("║ Drop Rate:          %11.2f%%                           ║%n", dropPct);

        // ---- per-worker stats ----
        if (workerStats != null && !workerStats.isEmpty()) {
            System.out.println("╠══════════════════════════════════════════════════════════════╣");
            System.out.println("║ THREAD STATISTICS                                             ║");
            for (WorkerStats ws : workerStats) {
                System.out.printf("║   %-8s processed: %12d                           ║%n",
                        ws.name(), ws.processed());
            }
        }

        // ---- app breakdown ----
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                   APPLICATION BREAKDOWN                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        List<Map.Entry<AppType, LongAdder>> sorted = new ArrayList<>(appCounts.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue().sum(), a.getValue().sum()));

        for (Map.Entry<AppType, LongAdder> entry : sorted) {
            long count = entry.getValue().sum();
            double pct = total > 0 ? 100.0 * count / total : 0;
            int bar    = (int)(pct / 5);
            System.out.printf("║ %-15s %8d %5.1f%% %-20s  ║%n",
                    entry.getKey().displayName(), count, pct, "#".repeat(bar));
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // ---- detected SNIs ----
        if (!detectedSnis.isEmpty()) {
            System.out.println("\n[Detected Domains / SNIs]");
            detectedSnis.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(e -> System.out.printf("  - %-45s → %s%n",
                            e.getKey(), e.getValue().displayName()));
        }
    }

    /** Snapshot of per-worker processed count for the report. */
    public record WorkerStats(String name, long processed) {}
}
