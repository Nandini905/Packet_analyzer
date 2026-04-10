# DPI Engine — Deep Packet Inspection System (Java)

A high-quality, interview-level Java implementation of a Deep Packet Inspection engine.
Converted from a full C++ implementation, preserving all architecture, logic, and threading design.

---

## What it does

- Reads real `.pcap` network capture files
- Parses Ethernet → IPv4 → TCP/UDP packet layers
- Extracts **SNI** from TLS Client Hello (identifies HTTPS destinations without decrypting)
- Extracts **HTTP Host** headers from plain HTTP traffic
- Classifies traffic into **23 application types** (YouTube, TikTok, Facebook, Netflix, Discord, Zoom, Spotify, and more)
- Applies **blocking rules** by IP, application, domain (wildcard support), or port
- Writes filtered (allowed) traffic to an output `.pcap` file
- Supports both **single-threaded** and **multi-threaded** processing modes

---

## Architecture

```
Reader Thread
    │  hash(5-tuple) % numLBs
    ▼
┌──────┐  ┌──────┐          ← Load Balancer threads
│ LB-0 │  │ LB-1 │
└──┬───┘  └──┬───┘
   │  hash(5-tuple) % totalFPs
   ▼          ▼
┌────┐ ┌────┐ ┌────┐ ┌────┐ ← FastPath Worker threads (DPI happens here)
│FP-0│ │FP-1│ │FP-2│ │FP-3│
└──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘
   └───────┴──────┴──────┘
               │
               ▼
        Output Queue
               │
               ▼
       OutputWriter Thread → output.pcap
```

**Consistent hashing** ensures the same network flow always goes to the same worker thread,
so per-flow state (SNI, classification, block status) is always accurate.

---

## Project Structure

```
src/main/java/com/dpi/
├── Main.java                          Entry point (CLI)
├── model/
│   ├── AppType.java                   23 app types + SNI→App mapping
│   ├── FiveTuple.java                 Flow identifier (src/dst IP, port, protocol)
│   ├── Flow.java                      Per-flow state (SNI, app, blocked flag)
│   └── Packet.java                    Self-contained packet wrapper for queues
├── reader/
│   ├── PcapReader.java                Binary PCAP file reader (handles endianness)
│   └── PcapWriter.java                Binary PCAP file writer
├── parser/
│   ├── PacketParser.java              Ethernet/IPv4/TCP/UDP layer parser
│   └── ParsedPacket.java              Parsed packet data structure
├── dpi/
│   ├── SNIExtractor.java              TLS Client Hello SNI extraction
│   ├── HTTPHostExtractor.java         HTTP Host header extraction
│   └── DNSExtractor.java              DNS query domain extraction
├── engine/
│   ├── DPIEngine.java                 Single-threaded engine
│   ├── RuleManager.java               Thread-safe blocking rules (IP/App/Domain/Port)
│   ├── ConnectionTracker.java         Per-worker flow table (LRU eviction)
│   └── Statistics.java                Thread-safe stats + report generation
└── multithreading/
    ├── MultiThreadedDPIEngine.java    Multi-threaded engine orchestrator
    ├── LoadBalancer.java              LB thread (routes packets to FP workers)
    ├── FastPathWorker.java            FP thread (classify + block + forward)
    └── QueueManager.java             Central queue registry (ArrayBlockingQueue)
```

---

## Requirements

- Java 17+
- No external runtime dependencies (SLF4J + Logback bundled in the fat JAR)

---

## Build

```bash
# Download dependencies
mkdir lib
# Download to lib/: slf4j-api-2.0.9.jar, logback-classic-1.4.11.jar, logback-core-1.4.11.jar
# from https://repo1.maven.org/maven2/

# Compile
javac --release 17 -cp "lib/*" -d out/classes $(find src -name "*.java")

# Package fat JAR
echo "Main-Class: com.dpi.Main" > manifest.txt
jar cfm dpi-engine.jar manifest.txt -C out/classes .
```

Or with Maven:
```bash
mvn clean package
```

---

## Usage

```bash
java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block all traffic from a source IP
  --block-app <app>      Block an application (YouTube, TikTok, Facebook, Netflix ...)
  --block-domain <dom>   Block a domain (exact or *.wildcard)
  --block-port <port>    Block a destination port
  --lbs <n>              Number of Load Balancer threads (default: 2)
  --fps <n>              FastPath workers per LB (default: 2)
  --rules <file>         Load blocking rules from a file
  --simple               Use single-threaded engine
```

---

## Examples

```bash
# Block YouTube and TikTok (multi-threaded, default)
java -jar dpi-engine.jar capture.pcap filtered.pcap --block-app YouTube --block-app TikTok

# Block all Facebook subdomains + a specific IP
java -jar dpi-engine.jar capture.pcap filtered.pcap --block-domain "*.facebook.com" --block-ip 192.168.1.50

# Block HTTPS entirely (port 443)
java -jar dpi-engine.jar capture.pcap filtered.pcap --block-port 443

# Single-threaded mode (simpler, good for debugging)
java -jar dpi-engine.jar capture.pcap filtered.pcap --simple --block-app Netflix

# Scale up threads for large captures
java -jar dpi-engine.jar big_capture.pcap filtered.pcap --lbs 4 --fps 4
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Java, Multi-threaded)           ║
╠══════════════════════════════════════════════════════════════╣
║   Load Balancers:      2                                       ║
║   FPs per LB:          2                                       ║
║   Total FP threads:    4                                       ║
╚══════════════════════════════════════════════════════════════╝

[FP-2] BLOCKED 192.168.1.100:58867 -> 142.250.185.110:443 reason=APP:YouTube
[FP-1] BLOCKED 192.168.1.100:64044 -> 157.240.1.35:443   reason=DOMAIN:www.facebook.com

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Forwarded:                    73                              ║
║ Dropped/Blocked:               4                              ║
║ Drop Rate:                  5.19%                             ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB-0     processed:           40                            ║
║   LB-1     processed:           37                            ║
║   FP-0     processed:           17                            ║
║   FP-1     processed:           20                            ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
║ YouTube         1   1.3%                                      ║
║ TikTok          1   1.3%                                      ║
║ Discord         1   1.3%                                      ║
║ DNS             4   5.2% #                                    ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains / SNIs]
  - www.youtube.com    → YouTube
  - www.tiktok.com     → TikTok
  - discord.com        → Discord
  - open.spotify.com   → Spotify
  - zoom.us            → Zoom
```

---

## Key Concepts

| Concept | Implementation |
|---|---|
| Flow tracking | `HashMap<FiveTuple, Flow>` per worker thread |
| Consistent hashing | `Math.abs(tuple.hashCode()) % numWorkers` |
| Thread-safe queues | `ArrayBlockingQueue` (bounded, blocking) |
| SNI extraction | Manual TLS Client Hello byte parsing |
| Rule thread-safety | `ReadWriteLock` per rule set |
| Stats | `LongAdder` (lock-free, high throughput) |
| Flow eviction | `LinkedHashMap` with LRU access order |

---

## Supported Applications

YouTube, TikTok, Facebook, Instagram, WhatsApp, Twitter/X, Netflix, Amazon,
Microsoft, Apple, Google, Telegram, Spotify, Zoom, Discord, GitHub, Cloudflare,
HTTP, HTTPS, DNS, TLS, QUIC
#   P a c k e t _ a n a l y z e r  
 