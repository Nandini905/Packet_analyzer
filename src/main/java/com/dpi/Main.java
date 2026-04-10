package com.dpi;

import com.dpi.engine.DPIEngine;
import com.dpi.multithreading.MultiThreadedDPIEngine;

/**
 * Entry point for the Java DPI Engine.
 *
 * Supports both single-threaded (--simple) and multi-threaded modes.
 *
 * Usage:
 *   java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]
 *
 * Options:
 *   --block-ip <ip>        Block all traffic from source IP
 *   --block-app <app>      Block application (YouTube, TikTok, Facebook, ...)
 *   --block-domain <dom>   Block domain (exact or *.wildcard)
 *   --block-port <port>    Block destination port
 *   --lbs <n>              Number of load balancer threads (default: 2)
 *   --fps <n>              FastPath workers per LB (default: 2)
 *   --rules <file>         Load blocking rules from file
 *   --simple               Use single-threaded engine (default: multi-threaded)
 *
 * Examples:
 *   java -jar dpi-engine.jar capture.pcap filtered.pcap \
 *       --block-app YouTube --block-app TikTok --block-ip 192.168.1.50
 *
 *   java -jar dpi-engine.jar capture.pcap filtered.pcap \
 *       --lbs 4 --fps 4 --block-domain "*.facebook.com"
 */
public class Main {

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputFile  = args[0];
        String outputFile = args[1];

        // ---- defaults ----
        int     numLBs    = 2;
        int     fpsPerLB  = 2;
        String  rulesFile = null;
        boolean simple    = false;

        // ---- collect blocking rules ----
        java.util.List<String> blockIPs     = new java.util.ArrayList<>();
        java.util.List<String> blockApps    = new java.util.ArrayList<>();
        java.util.List<String> blockDomains = new java.util.ArrayList<>();
        java.util.List<Integer> blockPorts  = new java.util.ArrayList<>();

        // ---- parse arguments ----
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip"     -> { if (i+1 < args.length) blockIPs.add(args[++i]); }
                case "--block-app"    -> { if (i+1 < args.length) blockApps.add(args[++i]); }
                case "--block-domain" -> { if (i+1 < args.length) blockDomains.add(args[++i]); }
                case "--block-port"   -> { if (i+1 < args.length) blockPorts.add(Integer.parseInt(args[++i])); }
                case "--lbs"          -> { if (i+1 < args.length) numLBs   = Integer.parseInt(args[++i]); }
                case "--fps"          -> { if (i+1 < args.length) fpsPerLB = Integer.parseInt(args[++i]); }
                case "--rules"        -> { if (i+1 < args.length) rulesFile = args[++i]; }
                case "--simple"       -> simple = true;
                default -> System.err.println("[Main] Unknown option: " + args[i]);
            }
        }

        boolean ok;

        if (simple) {
            // ---- Single-threaded engine ----
            DPIEngine engine = new DPIEngine();
            applyRules(engine, blockIPs, blockApps, blockDomains, blockPorts, rulesFile);
            ok = engine.processFile(inputFile, outputFile);

        } else {
            // ---- Multi-threaded engine ----
            MultiThreadedDPIEngine.Config cfg = new MultiThreadedDPIEngine.Config(numLBs, fpsPerLB);
            MultiThreadedDPIEngine engine = new MultiThreadedDPIEngine(cfg);
            applyRulesMT(engine, blockIPs, blockApps, blockDomains, blockPorts, rulesFile);
            ok = engine.processFile(inputFile, outputFile);
        }

        System.exit(ok ? 0 : 1);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static void applyRules(DPIEngine engine,
                                   java.util.List<String> ips,
                                   java.util.List<String> apps,
                                   java.util.List<String> domains,
                                   java.util.List<Integer> ports,
                                   String rulesFile) {
        if (rulesFile != null) engine.loadRules(rulesFile);
        ips.forEach(engine::blockIP);
        apps.forEach(engine::blockApp);
        domains.forEach(engine::blockDomain);
        ports.forEach(engine::blockPort);
    }

    private static void applyRulesMT(MultiThreadedDPIEngine engine,
                                     java.util.List<String> ips,
                                     java.util.List<String> apps,
                                     java.util.List<String> domains,
                                     java.util.List<Integer> ports,
                                     String rulesFile) {
        if (rulesFile != null) engine.loadRules(rulesFile);
        ips.forEach(engine::blockIP);
        apps.forEach(engine::blockApp);
        domains.forEach(engine::blockDomain);
        ports.forEach(engine::blockPort);
    }

    private static void printUsage() {
        System.out.println("""
╔══════════════════════════════════════════════════════════════╗
║          DPI Engine v2.0 (Java) - Deep Packet Inspection      ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block all traffic from source IP
  --block-app <app>      Block application (YouTube, TikTok, Facebook, Netflix...)
  --block-domain <dom>   Block domain (exact or *.wildcard)
  --block-port <port>    Block destination port
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FastPath workers per LB (default: 2)
  --rules <file>         Load blocking rules from file
  --simple               Use single-threaded engine

Examples:
  java -jar dpi-engine.jar capture.pcap out.pcap --block-app YouTube --block-app TikTok
  java -jar dpi-engine.jar capture.pcap out.pcap --lbs 4 --fps 4 --block-domain "*.facebook.com"
  java -jar dpi-engine.jar capture.pcap out.pcap --simple --block-ip 192.168.1.50
""");
    }
}
