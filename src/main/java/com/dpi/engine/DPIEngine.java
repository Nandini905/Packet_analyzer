package com.dpi.engine;

import com.dpi.dpi.DNSExtractor;
import com.dpi.dpi.HTTPHostExtractor;
import com.dpi.dpi.SNIExtractor;
import com.dpi.model.AppType;
import com.dpi.model.Flow;
import com.dpi.model.FiveTuple;
import com.dpi.model.Packet;
import com.dpi.reader.PcapReader;
import com.dpi.reader.PcapWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

/**
 * Single-threaded DPI Engine.
 *
 * C++ mapping: main() in main_working.cpp
 *
 * Processes packets one at a time in a single loop:
 *   Read → Parse → Classify → Check Rules → Forward/Drop
 *
 * This version is simpler and easier to understand than the multi-threaded
 * version. Use it for learning, debugging, or small captures.
 *
 * For production / large captures use {@link com.dpi.multithreading.MultiThreadedDPIEngine}.
 */
public class DPIEngine {

    private static final Logger log = LoggerFactory.getLogger(DPIEngine.class);

    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;

    // ---- shared components ----
    private final RuleManager  ruleManager;
    private final Statistics   stats;

    // ---- per-run state ----
    private final Map<FiveTuple, Flow> flowTable = new HashMap<>();

    public DPIEngine() {
        this.ruleManager = new RuleManager();
        this.stats       = new Statistics();
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
    // Main processing loop
    // =========================================================================

    /**
     * Process an entire PCAP file, writing allowed packets to outputFile.
     *
     * @param inputFile  path to input .pcap
     * @param outputFile path to output .pcap (filtered traffic)
     * @return true on success
     */
    public boolean processFile(String inputFile, String outputFile) {
        printBanner();
        log.info("[DPIEngine] Input:  {}", inputFile);
        log.info("[DPIEngine] Output: {}", outputFile);

        try (PcapReader reader = new PcapReader();
             PcapWriter writer = new PcapWriter(outputFile)) {

            reader.open(inputFile);
            writer.writeGlobalHeader(reader.getGlobalHeader());

            log.info("[DPIEngine] Processing packets...");
            Packet pkt;

            while ((pkt = reader.readNextPacket()) != null) {
                processPacket(pkt, writer);
            }

        } catch (IOException e) {
            log.error("[DPIEngine] Fatal error: {}", e.getMessage());
            return false;
        }

        // ---- final report ----
        stats.printReport(null);
        printFlowSummary();
        log.info("[DPIEngine] Output written to: {}", outputFile);
        return true;
    }

    // =========================================================================
    // Per-packet processing
    // =========================================================================

    private void processPacket(Packet pkt, PcapWriter writer) throws IOException {
        // ---- update global counters ----
        stats.totalPackets.increment();
        stats.totalBytes.add(pkt.data.length);
        if (pkt.tuple.protocol == PROTO_TCP) stats.tcpPackets.increment();
        else if (pkt.tuple.protocol == PROTO_UDP) stats.udpPackets.increment();

        // ---- get or create flow ----
        Flow flow = flowTable.computeIfAbsent(pkt.tuple, Flow::new);
        flow.touch(pkt.data.length);

        // ---- TCP state ----
        if (pkt.tuple.protocol == PROTO_TCP) {
            updateTCPState(flow, pkt.tcpFlags);
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
                flow.blocked = true;
                log.info("[BLOCKED] {} reason={} sni={}",
                        pkt.tuple, reason, flow.sni.isEmpty() ? "-" : flow.sni);
            }
        }

        // ---- record app stats ----
        stats.recordApp(flow.appType, flow.sni);

        // ---- forward or drop ----
        if (flow.blocked) {
            stats.dropped.increment();
        } else {
            stats.forwarded.increment();
            writer.writePacket(pkt);
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

        // 1. TLS SNI (port 443 or any port if it looks like TLS)
        if (pkt.tuple.dstPort == 443 && len > 50) {
            Optional<String> sni = SNIExtractor.extract(data, off, len);
            if (sni.isPresent()) {
                AppType app = AppType.fromSni(sni.get());
                flow.appType    = app;
                flow.sni        = sni.get();
                flow.classified = true;
                log.debug("[Classify] SNI={} → {}", sni.get(), app.displayName());
                return;
            }
        }

        // 2. HTTP Host header (port 80)
        if (pkt.tuple.dstPort == 80 && len > 10) {
            Optional<String> host = HTTPHostExtractor.extract(data, off, len);
            if (host.isPresent()) {
                AppType app = AppType.fromSni(host.get());
                flow.appType    = app;
                flow.sni        = host.get();
                flow.classified = true;
                log.debug("[Classify] HTTP Host={} → {}", host.get(), app.displayName());
                return;
            }
        }

        // 3. DNS (port 53)
        if (pkt.tuple.dstPort == 53 || pkt.tuple.srcPort == 53) {
            Optional<String> domain = DNSExtractor.extractQuery(data, off, len);
            if (domain.isPresent()) {
                flow.appType    = AppType.DNS;
                flow.sni        = domain.get();
                flow.classified = true;
                return;
            }
            flow.appType = AppType.DNS;
            return;
        }

        // 4. Port-based fallback (don't mark classified — SNI may arrive later)
        if (pkt.tuple.dstPort == 443) flow.appType = AppType.HTTPS;
        else if (pkt.tuple.dstPort == 80) flow.appType = AppType.HTTP;
    }

    // =========================================================================
    // TCP state machine
    // =========================================================================

    private static final int FLAG_SYN = 0x02;
    private static final int FLAG_ACK = 0x10;
    private static final int FLAG_FIN = 0x01;
    private static final int FLAG_RST = 0x04;

    private void updateTCPState(Flow flow, byte flags) {
        int f = flags & 0xFF;
        if ((f & FLAG_SYN) != 0) {
            if ((f & FLAG_ACK) != 0) flow.synAckSeen = true;
            else                     flow.synSeen    = true;
        }
        if ((f & FLAG_FIN) != 0) flow.finSeen = true;
    }

    // =========================================================================
    // Reporting helpers
    // =========================================================================

    private void printBanner() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0 (Java)                     ║");
        System.out.println("║              Single-threaded Mode                              ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    private void printFlowSummary() {
        System.out.printf("%n[Flow Summary] Active flows: %d%n", flowTable.size());
        flowTable.values().stream()
                .filter(f -> !f.sni.isEmpty())
                .sorted(Comparator.comparingLong((Flow f) -> f.packets).reversed())
                .limit(20)
                .forEach(f -> System.out.printf("  %-45s %-15s pkts=%-6d%s%n",
                        f.sni, f.appType.displayName(), f.packets,
                        f.blocked ? " [BLOCKED]" : ""));
    }
}
