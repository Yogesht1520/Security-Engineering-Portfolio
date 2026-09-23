# SOC Web Threat Analysis Report
> Source Log: `attack_demo.log` | Generated: 2026-09-23 20:30:24 UTC

## 🛡️ Executive Summary
- **Total Events Analyzed:** 273 (4,614 lines/sec)
- **Total Security Threats Identified:** 18
- **Unique Malicious IPs:** 5 across 5 countries
- **Peak Severity:** `CRITICAL` (14 Critical/High)
- **Primary Threat Vector:** Path Traversal (7 detections)

### Threat Category Breakdown
| Attack Type | Detections | Proportion |
|---|---|---|
| SQL Injection | 4 | 22.2% |
| Path Traversal | 7 | 38.9% |
| Scanner Reconnaissance | 5 | 27.8% |
| Brute-Force Attack | 1 | 5.6% |
| Status-Code Burst Anomaly | 1 | 5.6% |

## 🚨 Top Malicious Origins
| Attacker IP | Origin | rDNS / ASN | Threats | Top Vector | Severity |
|---|---|---|---|---|---|
| `45.33.32.156` | 🇺🇸 United States | Linode, LLC | 7 | Path Traversal | `CRITICAL` |
| `194.26.29.112` | 🇷🇺 Russia | Hostkey B.V. | 5 | Scanner Reconnaissance | `HIGH` |
| `185.220.101.5` | 🇳🇱 Netherlands | Tor Exit Node | 4 | SQL Injection | `CRITICAL` |
| `91.240.118.80` | 🇧🇬 Bulgaria | Telepoint Ltd | 1 | Brute-Force Attack | `HIGH` |
| `103.203.57.18` | 🇮🇳 India | Tata Communications | 1 | Status-Code Burst Anomaly | `MEDIUM` |

## 🔍 Findings Summary
Total findings: 18. Full details available in exported JSON/HTML reports.