<p align="center">
  <h1 align="center">ThreatFusion AI</h1>
  <p align="center">
    <strong>AI-Assisted Threat Detection &amp; Intelligence Platform for OT/ICS Networks</strong>
  </p>
  <p align="center">
    <em>C++ Detection Engine · LSTM Autoencoder · Isolation Forest · YARA · Suricata · Real-time SOC Dashboard</em>
  </p>
</p>

---

## Overview

ThreatFusion AI is a high-performance C++ security engine designed for **Operational Technology (OT)** and **Industrial Control System (ICS)** environments. It combines rule-based behavioral analysis, deep-learning anomaly detection, and threat intelligence correlation to identify cyberattacks targeting SCADA/ICS infrastructure in real time.

### Key Capabilities

| Category | Details |
| :--- | :--- |
| **Data Ingestion** | CSV, JSONL (Zeek/tshark), PCAP (via `tshark`), real-time TCP socket streaming (port 8080) |
| **Threat Intelligence** | IOC matching (IP, hash, protocol), STIX 2.x / TAXII v2 feed ingestion |
| **Detection Engine** | Rule-based behavioral detection for Modbus, S7Comm, DNP3, BACnet, IEC-104, IEC 61850/MMS, OPC UA, CODESYS |
| **Signature Scanning** | Production-grade YARA rules (Stuxnet, Triton, Industroyer, PipeDream), DPI-level Suricata rules |
| **AI Anomaly Detection** | C++ Isolation Forest, LSTM Autoencoder (PyTorch training + LibTorch JIT inference) |
| **Classification** | Reconnaissance, Command Injection, DoS, Unauthorized Firmware Update, Malware Signature, Network Signature |
| **Risk Scoring** | `Asset Criticality × Threat Severity × Confidence Score` (0–100), with multi-detection correlation boost |
| **Live Dashboard** | Premium dark-theme real-time SOC console with interactive OT topology, protocol distribution, and alert streaming |
| **Evaluation** | Confusion matrix (TP/TN/FP/FN), Precision, Recall, F1, Accuracy, FPR, detection latency (avg/p95/max) |

---

## Repository Layout

```
├── include/threatfusion/   C++ headers (Event, Detectors, Scorers, Ingestion)
├── src/                    C++ engine implementation and CLI entry point
├── data/                   Sample IOC, rule, CSV, JSONL event data
├── rules/                  YARA, Suricata, and Snort signature rules
├── tools/                  Python utilities (normalization, training, PCAP generation, dashboard server)
├── lab/                    Docker Compose OT/ICS simulation lab and attack scripts
├── dashboard/              Real-time SOC Console (React + Chart.js + Tailwind)
├── datasets/               Dataset integration guide and manifest (MSU ICS)
├── models/                 Trained model artifacts (LSTM Autoencoder weights)
├── tests/                  C++ unit tests
├── out/                    Generated alerts, incidents, and evaluation metrics
├── captures/               PCAP capture files
└── samples/                Harmless lab payload markers for YARA validation
```

---

## Getting Started

### Prerequisites

- **C++17** compiler (MSVC recommended on Windows, GCC/Clang on Linux)
- **CMake** ≥ 3.14
- **Python** ≥ 3.8 (for tools and dashboard server)
- **Optional**: [LibTorch](https://pytorch.org/cppdocs/installing.html), [tshark](https://www.wireshark.org/), [Suricata](https://suricata.io/), [YARA](https://virustotal.github.io/yara/)

### Build with CMake

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Build with LibTorch (Optional)

```bash
cmake -S . -B build -DUSE_LIBTORCH=ON -DCMAKE_PREFIX_PATH="/path/to/libtorch"
cmake --build build --config Release
```

### Alternative: MinGW Build (Windows)

```powershell
g++ -std=c++17 -I include src/*.cpp -o build/threatfusion.exe -lws2_32
```

> **Note:** MinGW builds support the core engine and simulated LSTM fallback. Real LibTorch JIT inference requires an MSVC build.

---

## Usage

### Core CSV Pipeline

```bash
./build/threatfusion.exe \
  --events data/sample_ot_events.csv \
  --format csv \
  --baseline data/sample_ot_events.csv \
  --baseline-format csv \
  --iocs data/iocs.csv \
  --rules data/behavior_rules.csv \
  --alerts out/alerts.csv \
  --incidents out/incidents.csv \
  --metrics out/metrics.txt \
  --threshold 60
```

### JSONL Events (Zeek/tshark)

```bash
./build/threatfusion.exe \
  --events data/sample_zeek_ot_events.jsonl \
  --format jsonl \
  --iocs data/iocs.csv \
  --rules data/behavior_rules.csv \
  --threshold 60
```

### YARA Signature Scanning

```bash
./build/threatfusion.exe \
  --events data/sample_yara_family_events.csv \
  --format csv \
  --yara /path/to/yara.exe \
  --yara-rules rules/yara/ics_malware_indicators.yar \
  --threshold 60
```

### PCAP Ingestion with Suricata

```bash
# Generate a valid BACnet/IP test PCAP
python tools/generate_bacnet_pcap.py

# Run the full pipeline
./build/threatfusion.exe \
  --events captures/valid_bacnet.pcap \
  --format pcap \
  --tshark /path/to/tshark.exe \
  --suricata /path/to/suricata.exe \
  --suricata-rules rules/suricata/local_ics.rules \
  --threshold 60
```

### Real-time TCP Streaming

```bash
# Start the C++ engine in stream mode (listens on port 8080)
./build/threatfusion.exe --stream --port 8080

# Stream MSU ICS dataset events to the engine
python tools/collector_daemon.py --input data/msu_events.jsonl --port 8080 --rate 5
```

---

## SOC Dashboard

ThreatFusion includes a premium real-time **Security Operations Center** dashboard.

```bash
# Start the dashboard server
python tools/dashboard_server.py

# Open in browser
# → http://localhost:8000
```

**Dashboard Features:**
- Real-time alert volume activity chart (dynamic time-bucketing)
- OT Protocol Distribution (Modbus TCP, DNP3, S7Comm, SMB, TCP/UDP)
- Severity breakdown (Critical / High / Medium / Low)
- Alert Log Stream Explorer with expandable raw telemetry payloads
- Industrial OT Asset Inventory with live risk scoring
- Detection Rules browser (YARA, Suricata, Snort, ML models)
- Attack Simulation mode for live demo
- Stream log management (Clear Stream with inline confirmation)

---

## Dataset Integration

ThreatFusion supports the **Mississippi State University (MSU) ICS Modbus RTU** dataset for training and evaluation.

```bash
# Normalize the MSU dataset
python tools/normalize_msu_ics.py --input path/to/MSU_dataset.csv --output data/msu_events.jsonl

# Stream to C++ engine
python tools/collector_daemon.py --input data/msu_events.jsonl --port 8080 --rate 5
```

See [`datasets/dataset_manifest.csv`](datasets/dataset_manifest.csv) for the full dataset registry.

---

## Benchmark Results

Evaluated on the **MSU ICS Modbus RTU dataset** across 4 attack categories with three detection configurations:

| Dataset | LSTM (Auto) | LSTM (Tuned) | Hybrid (IF + LSTM) | Optimal Configuration |
| :--- | :---: | :---: | :---: | :--- |
| **Multiclass** | 68.2% | **97.9%** | **97.9%** | LSTM Only |
| **Command Injection** | 59.7% | **93.8%** | **93.8%** | LSTM Only |
| **Response Injection** | 64.5% | 76.7% | **81.5%** | 0.7 × IF + 0.3 × LSTM |
| **DoS** | 91.0% | 93.6% | **94.1%** | 0.8 × IF + 0.2 × LSTM |

**Key Findings:**
- **Hybrid Fusion** suppressed false positives on Response Injection and DoS, achieving **81.5%** F1 (+4.8% over pure LSTM).
- **Tuned LSTM** reaches near-optimal detection on sequential attacks (Multiclass F1: **97.9%**, Command Injection F1: **93.8%**).

---

## Simulation Lab

A Docker Compose-based OT/ICS simulation environment for generating benign and attack traffic.

See [`lab/README.md`](lab/README.md) for setup instructions.

**Included tools:**
- Modbus PLC simulator
- HMI client
- Modbus scan / write / flood traffic generator
- OPC UA probe

---

## Metrics Semantics

The confusion matrix evaluates only events labeled `benign` or `malicious`:

- **Unlabeled events**: Events with no label or intermediate labels (e.g., `suspicious`) are excluded from the confusion matrix.
- **External alerts**: Alerts generated by external tools (e.g., Suricata PCAP alerts) are counted separately as `external_alerts`.

This prevents unlabeled operational traffic from being incorrectly counted as true negatives.

---

## Known Limitations

- **YARA samples**: The bundled lab marker files are harmless placeholders, not real malware. Validate rules against approved malware datasets before making production claims.
- **PCAP parsing**: The `tshark` field parser may require tuning for specific Wireshark versions or proprietary protocol plugins.
- **LibTorch on Windows**: Real TorchScript inference requires an MSVC-compatible build. MinGW builds use a simulated LSTM fallback.

---

## License

This project is developed as part of an academic research initiative. Please contact the repository owner for licensing information.
