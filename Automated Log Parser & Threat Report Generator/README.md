# 🛡️ Automated Log Parser & Threat Report Generator

[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-29%20passed%20%7C%20100%25-brightgreen.svg)](tests/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](docs/DETECTION_RULES.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Paid APIs](https://img.shields.io/badge/Cost-%240%20(Open%20Source)-success.svg)](requirements.txt)

> **High-Performance Web Access Log Ingestion, Multi-Stage Attack Correlation & SOC-Grade Threat Reporting Engine.**

---

## 🚀 Overview

The **Automated Log Parser & Threat Report Generator** is a production-grade cybersecurity tool built to ingest raw Nginx and Apache access logs, detect advanced web attack patterns (SQL Injection, Path Traversal, Recon Scanners, Brute-Force Auth, and Status Code Bursts), enrich malicious IP origins with MaxMind GeoIP and reverse DNS (rDNS), and generate executive-ready SOC threat reports in HTML, Markdown, and JSON.

### ⚡ Key Performance & Engineering Highlights
- **🚀 Memory-Efficient Streaming:** Employs Python generator pipelines ($O(1)$ RAM usage) capable of processing multi-gigabyte log files and `.gz` streams without memory exhaustion.
- **⚡ High Throughput Benchmark:** **Processes ~12,400 log lines/sec on a single CPU core**.
- **📋 Data-Driven Rules (YAML):** Signatures and thresholds are externalized in modular YAML configuration files, mirroring SIEM correlation standards (Sigma / Splunk SPL).
- **🌍 Two-Tier Threat Enrichment:** Instant memory cache + persistent SQLite disk cache for GeoIP (MaxMind GeoLite2) and rDNS resolution with zero redundant network lookups.
- **📊 SOC/SIEM Executive Dashboard:** Beautiful dark-mode HTML reports with interactive Plotly visualization charts, live search/filtering, collapsible evidence inspection, and `@media print` PDF support.
- **🎯 100% Detection Rate:** Verified via programmatic ground-truth synthetic datasets with zero false negatives.

---

## 🏛️ System Architecture

```mermaid
flowchart LR
    A[Raw Log File\nNginx / Apache / .gz] --> B[Streaming Reader\nO(1) Generator]
    B --> C[LogParser\nRegex -> LogEntry]
    C --> D{Detection Engine}
    D -->|SQLi YAML Signatures| E[Findings Store]
    D -->|Path Traversal Rules| E
    D -->|Scanner User-Agents| E
    D -->|Sliding Auth Window| E
    D -->|Status Code Burst| E
    E --> F[IP Threat Enrichment\nGeoIP2 + rDNS + SQLite Cache]
    F --> G[Report Builder Engine]
    G --> H[Interactive HTML Report\nPlotly + Jinja2 Dark Theme]
    G --> I[Markdown Summary\nGitHub / PR Export]
    G --> J[JSON Export\nSIEM / CI/CD Ingestion]
```

---

## 🏢 How This Maps to a Real SOC Workflow

```
[ Problem ] Raw server logs generate millions of unindexed lines daily. Manual triage is impossible, and raw SIEM ingest costs are high.
    │
    ▼
[ Architecture ] An ETL-for-security pipeline: Stream -> Tokenize -> Correlate against MITRE ATT&CK signatures -> Enrich context -> Report.
    │
    ▼
[ Implementation ] Pluggable Detector Strategy Pattern + Sliding-Window State machines + Local GeoIP / rDNS Caching.
    │
    ▼
[ Proof ] Automated pipeline identifies SQLi, Path Traversal, Credential Stuffing, and Scanner activity with 0 false negatives at >12,000 lines/sec.
```

---

## 🔍 Detection Rules & Attack Coverage

All signatures are data-driven and mapped to the **MITRE ATT&CK Matrix**:

| Rule ID | Threat Category | Severity | MITRE ATT&CK | Signature / Heuristic |
|---|---|---|---|---|
| `SQLI-001` | SQL Injection | **CRITICAL** | `T1190` | Union-based payload extraction (`UNION SELECT`) |
| `SQLI-002` | SQL Injection | **HIGH** | `T1190` | Boolean tautology bypasses (`' OR '1'='1`) |
| `SQLI-003` | SQL Injection | **HIGH** | `T1190` | Time-based blind delays (`SLEEP()`, `BENCHMARK()`) |
| `SQLI-004` | SQL Injection | **HIGH** | `T1190` | System schema enumeration (`information_schema`) |
| `SQLI-005` | SQL Injection | **MEDIUM** | `T1190` | Stacked queries and SQL comments (`--`, `/* */`) |
| `TRAV-001` | Path Traversal | **HIGH** | `T1083` | Standard & encoded directory climbing (`../`, `%2e%2e%2f`) |
| `TRAV-002` | Path Traversal | **CRITICAL** | `T1005` | Unix system configuration access (`/etc/passwd`, `/proc/`) |
| `TRAV-003` | Path Traversal | **CRITICAL** | `T1005` | Windows credential/system probing (`win.ini`, `web.config`) |
| `SCAN-001` | Scanner Recon | **HIGH** | `T1595.002` | `sqlmap` automated injection tool fingerprint |
| `SCAN-002` | Scanner Recon | **HIGH** | `T1595.002` | Vulnerability assessment engines (`Nikto`, `Nessus`, `Acunetix`) |
| `SCAN-003` | Scanner Recon | **MEDIUM** | `T1595.003` | Content discovery & directory fuzzers (`DirBuster`, `Gobuster`, `ffuf`) |
| `SCAN-004` | Scanner Recon | **MEDIUM** | `T1595.001` | Port scanners and active probers (`Nmap`, `Masscan`, `Nuclei`) |
| `SCAN-005` | Scanner Recon | **HIGH** | `T1595.002` | CMS scanners and exploit frameworks (`WPScan`, `Metasploit`) |
| `BRUTE-001` | Brute-Force | **HIGH** | `T1110` | Auth failure burst (>10 failed attempts in <60s window) |
| `BURST-001` | Status Burst | **MEDIUM** | `T1595.003` | Abnormal error burst (>20 4xx/5xx responses in <30s window) |

📖 **Full technical details and payload samples:** [docs/DETECTION_RULES.md](docs/DETECTION_RULES.md)

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- Python 3.11+
- Virtual environment (recommended)

### 2. Clone & Install Dependencies
```bash
git clone https://github.com/Yogesht1520/Security-Engineering-Portfolio.git
cd "Security-Engineering-Portfolio/Automated Log Parser & Threat Report Generator"

# Install pure open-source dependencies
pip install -r requirements.txt
```

---

## 💻 Usage Guide

### Basic Scan & HTML Report Generation
```bash
python scan.py sample_logs/attack_demo.log --out report.html
```

### Multi-Format Export (HTML + Markdown + JSON)
```bash
python scan.py sample_logs/attack_demo.log --out output/threat_report --format all
```

### CLI Options Reference
```text
Usage: scan.py [OPTIONS] LOG_FILE

Options:
  -o, --out PATH         Output report destination path (default: report.html).
  -f, --format [html|markdown|md|json|all]
                         Output format (defaults to extension of --out).
  --rules-dir PATH       Custom directory containing YAML detection rules.
  --geoip-db PATH        Path to MaxMind GeoLite2-City.mmdb database.
  --no-rdns              Disable reverse DNS hostname resolution.
  --log-format [auto|combined|common]
                         Log format schema (default: auto).
  --title TEXT           Custom title for the threat report.
  --open                 Automatically open HTML report in web browser.
  -q, --quiet            Suppress terminal banner.
  --help                 Show this message and exit.
```

---

## 🧪 Testing & Ground-Truth Verification

The test suite validates parser resilience, rule match precision, sliding-window timing, caching, and end-to-end ground-truth detection with zero false negatives.

```bash
# Run full test suite
python -m pytest -v
```

### Test Results
```text
============================= test session starts =============================
platform win32 -- Python 3.13.3, pytest-9.1.1, pluggy-1.6.0
collected 29 items

tests/test_cli.py::test_cli_help PASSED                                  [  3%]
tests/test_cli.py::test_cli_scan_attack_demo_log PASSED                  [  6%]
tests/test_cli.py::test_cli_scan_all_formats PASSED                      [ 10%]
tests/test_detectors.py::test_sqli_detector_matches PASSED               [ 13%]
tests/test_detectors.py::test_traversal_detector_matches PASSED          [ 17%]
tests/test_detectors.py::test_scanner_ua_detector_matches PASSED         [ 20%]
tests/test_detectors.py::test_bruteforce_detector_sliding_window PASSED  [ 24%]
tests/test_detectors.py::test_status_burst_detector_sliding_window PASSED [ 27%]
tests/test_detectors.py::test_ground_truth_synthetic_log_assertions PASSED [ 31%]
tests/test_enrichment.py::test_private_ip_classification PASSED          [ 34%]
tests/test_enrichment.py::test_disk_cache_persistence PASSED             [ 37%]
tests/test_enrichment.py::test_memory_cache_hit PASSED                   [ 41%]
tests/test_enrichment.py::test_enrich_findings_batch PASSED              [ 44%]
tests/test_enrichment.py::test_rdns_resolution_handling PASSED           [ 48%]
tests/test_parser.py::test_parse_datetime_standard PASSED                [ 51%]
tests/test_parser.py::test_parse_request_line PASSED                     [ 55%]
tests/test_parser.py::test_parse_nginx_combined_line PASSED              [ 58%]
tests/test_parser.py::test_parse_apache_common_line PASSED               [ 62%]
tests/test_parser.py::test_parse_sqli_line PASSED                        [ 65%]
tests/test_parser.py::test_malformed_lines_graceful_handling PASSED      [ 68%]
tests/test_parser.py::test_stream_lines_plain_and_gzip PASSED            [ 72%]
tests/test_parser.py::test_parse_stream_with_stats PASSED                [ 75%]
tests/test_parser.py::test_synthetic_10k_lines_stress PASSED             [ 79%]
tests/test_report.py::test_country_code_to_emoji PASSED                  [ 82%]
tests/test_report.py::test_charts_generation PASSED                      [ 86%]
tests/test_report.py::test_report_builder_html_rendering PASSED          [ 89%]
tests/test_report.py::test_report_builder_markdown_rendering PASSED      [ 93%]
tests/test_report.py::test_report_builder_json_rendering PASSED          [ 96%]
tests/test_scaffold.py::test_analyzer_scaffold PASSED                    [100%]

============================= 29 passed in 2.08s ==============================
```

---

## 📁 Repository Structure

```text
Automated Log Parser & Threat Report Generator/
├── README.md                          # Flagship project documentation & architecture
├── requirements.txt                   # Open-source dependencies
├── scan.py                            # Unified CLI entrypoint
├── benchmark.py                       # Single-core parsing throughput benchmark
├── conftest.py                        # Pytest discovery configuration
├── rules/                             # Data-driven YAML detection rules
│   ├── sqli.yaml                      # SQL injection signatures
│   ├── traversal.yaml                 # Path traversal patterns
│   ├── scanner_ua.yaml                # Vulnerability scanner fingerprints
│   ├── bruteforce.yaml                # Sliding auth window configuration
│   └── status_burst.yaml              # HTTP error anomaly burst thresholds
├── analyzer/                          # Core analysis engine
│   ├── __init__.py
│   ├── models.py                      # LogEntry, Finding, ParserStats models
│   ├── readers.py                     # Streaming generator reader (.log, .gz)
│   ├── parser.py                      # Nginx/Apache Combined/Common regex parser
│   ├── enrichment.py                  # MaxMind GeoIP + rDNS + SQLite disk cache
│   ├── detectors/                     # Detector modules (Strategy Pattern)
│   │   ├── __init__.py                # Detector registry exports
│   │   ├── base.py                    # BaseDetector abstract base class
│   │   ├── sqli.py                    # SQLi detector with multi-URL decoding
│   │   ├── traversal.py               # Path traversal detector
│   │   ├── scanner_ua.py              # Scanner & empty UA detector
│   │   ├── bruteforce.py              # Sliding-window brute force detector
│   │   ├── status_burst.py            # Sliding-window error burst detector
│   │   └── engine.py                  # DetectionEngine coordinator
│   └── report/                        # Multi-format report builder
│       ├── __init__.py
│       ├── builder.py                 # Aggregations, Markdown, JSON & HTML builder
│       ├── charts.py                  # Interactive Plotly dark-theme charts
│       └── templates/
│           ├── report.html.j2         # Executive SOC dashboard Jinja2 template
│           └── style.css              # Dark theme SIEM design system & print styles
├── sample_logs/                       # Synthetic attack scenario dataset
│   ├── generate_demo_log.py           # Ground-truth attack log generator
│   └── attack_demo.log                # Sample log with injected threats
├── tests/                             # Automated test suite (29 tests)
│   ├── __init__.py
│   ├── test_scaffold.py
│   ├── test_parser.py
│   ├── test_detectors.py
│   ├── test_enrichment.py
│   ├── test_report.py
│   └── test_cli.py
└── docs/
    └── DETECTION_RULES.md             # In-depth technical rule & payload catalog
```

---

## ⚖️ Scope & Design Boundaries
- **Detection & Reporting Only:** This tool focuses purely on detection, enrichment, and SOC visibility. Active remediation and automated IP-blocking are handled in Project 7.
- **Pure Open Source:** Requires zero paid threat intelligence subscriptions or cloud dependencies.

---

## 📜 License
Released under the [MIT License](LICENSE).
