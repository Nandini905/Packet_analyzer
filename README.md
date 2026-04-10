# 🔍 Deep Packet Inspection Engine

> A high-performance network traffic analyzer that inspects and classifies packet payloads at Layer 7 (Application Layer) in real time.

![C++](https://img.shields.io/badge/C++-00599C?style=flat&logo=c%2B%2B&logoColor=white)
![Java](https://img.shields.io/badge/Java-ED8B00?style=flat&logo=java&logoColor=white)
![Network Security](https://img.shields.io/badge/Domain-Network%20Security-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📌 Problem Statement

Traditional firewalls inspect only packet headers (IP/port). They fail to detect threats hidden inside packet payloads — such as malware disguised as HTTP traffic or data exfiltration over DNS.

This engine performs **Deep Packet Inspection (DPI)**: analyzing the full content of network packets to identify protocols, detect anomalies, and enable intelligent traffic filtering — even on non-standard ports.

---

## ✨ Features

- ✅ Real-time packet capture and payload analysis
- ✅ Protocol classification (HTTP, DNS, FTP, SMTP, etc.)
- ✅ Pattern matching using signature-based detection
- ✅ Traffic statistics and flow tracking
- ✅ Java-based reporting layer with exportable logs
- ✅ Supports both live capture and PCAP file analysis

---

## 🏗️ Architecture Overview
┌─────────────────────────────────────────────────┐
│              Network Interface / PCAP File       │
└──────────────────────┬──────────────────────────┘
│
┌────────▼────────┐
│  Packet Capture  │  ← C++ / libpcap
│   (Raw Layer)    │
└────────┬────────┘
│
┌────────▼────────┐
│ Payload Parser   │  ← C++ Engine
│ & DPI Core       │
└────────┬────────┘
│
┌─────────────┼─────────────┐
│             │             │
┌──────▼──┐   ┌──────▼──┐  ┌──────▼──┐
│Protocol │   │Signature│  │  Flow   │
│Classifier│  │Matcher  │  │ Tracker │
└──────┬──┘   └──────┬──┘  └──────┬──┘
└─────────────┼─────────────┘
│
┌────────▼────────┐
│  Java Reporting  │  ← Java Layer
│  & Alert Engine  │
└─────────────────┘
---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Packet Capture | C++, libpcap |
| DPI Core Engine | C++ |
| Reporting Layer | Java |
| Protocol Detection | Custom signature matching |
| Build System | Makefile / Maven |

---

## ⚙️ How to Run

### Prerequisites
- GCC / G++ (C++17 or higher)
- libpcap (`sudo apt install libpcap-dev`)
- Java JDK 11+
- Maven

### Build & Run

```bash
# Clone the repository
git clone https://github.com/Nandini905/deep-packet-inspection-engine.git
cd deep-packet-inspection-engine

# Build the C++ engine
make

# Run on a network interface (requires sudo)
sudo ./dpi_engine -i eth0

# OR analyze a PCAP file
./dpi_engine -f sample.pcap

# Generate Java report
cd reporting/
mvn package
java -jar target/dpi-report.jar ../output/results.json
```

---

## 📂 Project Structure
deep-packet-inspection-engine/
├── src/
│   ├── capture/        # Packet capture module (libpcap)
│   ├── parser/         # Payload parsing & protocol detection
│   ├── signatures/     # Protocol signature definitions
│   └── tracker/        # Flow tracking & statistics
├── reporting/          # Java reporting & alerting module
│   └── src/main/java/
├── samples/            # Sample PCAP files for testing
├── output/             # Generated analysis reports
├── Makefile
└── README.md
---

## 🔮 Future Enhancements

- [ ] ML-based anomaly detection
- [ ] Web dashboard for real-time visualization
- [ ] SSL/TLS traffic analysis
- [ ] Integration with Snort/Suricata rules

---

## 👩‍💻 Author

**Nandini** — BTech IT Student  
[GitHub](https://github.com/Nandini905) · [LinkedIn] (https://www.linkedin.com/in/nandinipathak-tech)
