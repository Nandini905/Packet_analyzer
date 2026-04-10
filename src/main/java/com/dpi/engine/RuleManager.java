package com.dpi.engine;

import com.dpi.model.AppType;
import com.dpi.model.FiveTuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe manager for all blocking/filtering rules.
 *
 * C++ mapping: class Rules (dpi_mt.cpp) + class RuleManager (rule_manager.h/cpp)
 *
 * Supports four rule types:
 *   1. IP-based   – block all traffic from a source IP
 *   2. App-based  – block a classified application (e.g. YouTube)
 *   3. Domain     – block by SNI/Host substring or *.wildcard pattern
 *   4. Port       – block a destination port
 *
 * Thread-safety strategy:
 *   - ReadWriteLock per rule set → many concurrent readers, exclusive writer
 *   - CopyOnWriteArrayList for domain patterns (read-heavy, rare writes)
 */
public class RuleManager {

    private static final Logger log = LoggerFactory.getLogger(RuleManager.class);

    // ---- IP rules ----
    private final ReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<Integer>  blockedIps = new HashSet<>();

    // ---- App rules ----
    private final ReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<AppType>  blockedApps = new HashSet<>();

    // ---- Domain rules ----
    private final ReadWriteLock domainLock    = new ReentrantReadWriteLock();
    private final Set<String>   blockedDomains  = new HashSet<>();          // exact (lower-case)
    private final List<String>  domainPatterns  = new CopyOnWriteArrayList<>(); // wildcard

    // ---- Port rules ----
    private final ReadWriteLock portLock = new ReentrantReadWriteLock();
    private final Set<Integer>  blockedPorts = new HashSet<>();

    // =========================================================================
    // IP blocking
    // =========================================================================

    public void blockIP(String ip) {
        blockIP(FiveTuple.parseIp(ip));
    }

    public void blockIP(int ip) {
        ipLock.writeLock().lock();
        try { blockedIps.add(ip); }
        finally { ipLock.writeLock().unlock(); }
        log.info("[RuleManager] Blocked IP: {}", FiveTuple.ipToString(ip));
    }

    public void unblockIP(String ip) {
        int parsed = FiveTuple.parseIp(ip);
        ipLock.writeLock().lock();
        try { blockedIps.remove(parsed); }
        finally { ipLock.writeLock().unlock(); }
    }

    public boolean isIPBlocked(int ip) {
        ipLock.readLock().lock();
        try { return blockedIps.contains(ip); }
        finally { ipLock.readLock().unlock(); }
    }

    // =========================================================================
    // App blocking
    // =========================================================================

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.add(app); }
        finally { appLock.writeLock().unlock(); }
        log.info("[RuleManager] Blocked app: {}", app.displayName());
    }

    public void blockApp(String name) {
        AppType app = AppType.fromDisplayName(name);
        if (app == AppType.UNKNOWN) {
            log.warn("[RuleManager] Unknown app name: {}", name);
            return;
        }
        blockApp(app);
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try { blockedApps.remove(app); }
        finally { appLock.writeLock().unlock(); }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try { return blockedApps.contains(app); }
        finally { appLock.readLock().unlock(); }
    }

    // =========================================================================
    // Domain blocking  (exact match + *.wildcard)
    // =========================================================================

    /**
     * Block a domain. Supports wildcard prefix: "*.facebook.com" blocks all
     * subdomains of facebook.com as well as facebook.com itself.
     */
    public void blockDomain(String domain) {
        String lower = domain.toLowerCase();
        domainLock.writeLock().lock();
        try {
            if (lower.contains("*")) domainPatterns.add(lower);
            else                     blockedDomains.add(lower);
        } finally { domainLock.writeLock().unlock(); }
        log.info("[RuleManager] Blocked domain: {}", domain);
    }

    public void unblockDomain(String domain) {
        String lower = domain.toLowerCase();
        domainLock.writeLock().lock();
        try {
            if (lower.contains("*")) domainPatterns.remove(lower);
            else                     blockedDomains.remove(lower);
        } finally { domainLock.writeLock().unlock(); }
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isBlank()) return false;
        String lower = domain.toLowerCase();
        domainLock.readLock().lock();
        try {
            if (blockedDomains.contains(lower)) return true;
            for (String pattern : domainPatterns) {
                if (matchesWildcard(lower, pattern)) return true;
            }
            return false;
        } finally { domainLock.readLock().unlock(); }
    }

    /**
     * Wildcard matching: "*.example.com" matches "sub.example.com" and "example.com".
     * Mirrors C++ RuleManager::domainMatchesPattern().
     */
    private static boolean matchesWildcard(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            return domain.endsWith(suffix) || domain.equals(pattern.substring(2));
        }
        return false;
    }

    // =========================================================================
    // Port blocking
    // =========================================================================

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.add(port & 0xFFFF); }
        finally { portLock.writeLock().unlock(); }
        log.info("[RuleManager] Blocked port: {}", port);
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try { blockedPorts.remove(port & 0xFFFF); }
        finally { portLock.writeLock().unlock(); }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try { return blockedPorts.contains(port & 0xFFFF); }
        finally { portLock.readLock().unlock(); }
    }

    // =========================================================================
    // Combined check  (mirrors C++ RuleManager::shouldBlock())
    // =========================================================================

    /**
     * Check whether a packet/connection should be blocked.
     * Priority order: IP → Port → App → Domain.
     *
     * @return a {@link BlockReason} if blocked, or {@code null} if allowed
     */
    public BlockReason shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp))
            return new BlockReason(BlockReason.Type.IP, FiveTuple.ipToString(srcIp));
        if (isPortBlocked(dstPort))
            return new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort));
        if (isAppBlocked(app))
            return new BlockReason(BlockReason.Type.APP, app.displayName());
        if (isDomainBlocked(domain))
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        return null; // not blocked
    }

    // =========================================================================
    // Persistence
    // =========================================================================

    public boolean saveRules(String filename) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(filename))) {
            pw.println("[BLOCKED_IPS]");
            ipLock.readLock().lock();
            try { blockedIps.forEach(ip -> pw.println(FiveTuple.ipToString(ip))); }
            finally { ipLock.readLock().unlock(); }

            pw.println("\n[BLOCKED_APPS]");
            appLock.readLock().lock();
            try { blockedApps.forEach(a -> pw.println(a.displayName())); }
            finally { appLock.readLock().unlock(); }

            pw.println("\n[BLOCKED_DOMAINS]");
            domainLock.readLock().lock();
            try {
                blockedDomains.forEach(pw::println);
                domainPatterns.forEach(pw::println);
            } finally { domainLock.readLock().unlock(); }

            pw.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try { blockedPorts.forEach(pw::println); }
            finally { portLock.readLock().unlock(); }

            log.info("[RuleManager] Rules saved to: {}", filename);
            return true;
        } catch (IOException e) {
            log.error("[RuleManager] Save failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line, section = "";
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) { section = line; continue; }
                switch (section) {
                    case "[BLOCKED_IPS]"     -> blockIP(line);
                    case "[BLOCKED_APPS]"    -> blockApp(line);
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]"   -> blockPort(Integer.parseInt(line));
                }
            }
            log.info("[RuleManager] Rules loaded from: {}", filename);
            return true;
        } catch (IOException e) {
            log.error("[RuleManager] Load failed: {}", e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();     try { blockedIps.clear(); }     finally { ipLock.writeLock().unlock(); }
        appLock.writeLock().lock();    try { blockedApps.clear(); }    finally { appLock.writeLock().unlock(); }
        domainLock.writeLock().lock(); try { blockedDomains.clear(); domainPatterns.clear(); } finally { domainLock.writeLock().unlock(); }
        portLock.writeLock().lock();   try { blockedPorts.clear(); }   finally { portLock.writeLock().unlock(); }
    }

    // =========================================================================
    // Stats
    // =========================================================================

    public RuleStats getStats() {
        int ips, apps, domains, ports;
        ipLock.readLock().lock();     try { ips     = blockedIps.size(); }     finally { ipLock.readLock().unlock(); }
        appLock.readLock().lock();    try { apps    = blockedApps.size(); }    finally { appLock.readLock().unlock(); }
        domainLock.readLock().lock(); try { domains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }
        portLock.readLock().lock();   try { ports   = blockedPorts.size(); }   finally { portLock.readLock().unlock(); }
        return new RuleStats(ips, apps, domains, ports);
    }

    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {}

    // =========================================================================
    // BlockReason inner class
    // =========================================================================

    /** Describes why a packet was blocked. Mirrors C++ RuleManager::BlockReason. */
    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public final Type   type;
        public final String detail;
        public BlockReason(Type type, String detail) { this.type = type; this.detail = detail; }
        @Override public String toString() { return type + ":" + detail; }
    }
}
