# 🛡️ Detection Rules & Attack Signatures Catalog

This document provides a comprehensive technical catalog of the data-driven security detection rules implemented in the **Automated Log Parser & Threat Report Generator**.

Each rule is defined externally in YAML format under the `rules/` directory, decoupling threat intelligence and signature updates from core application code (matching real-world SIEM correlation rules such as Sigma and Splunk SPL).

---

## Summary Matrix & MITRE ATT&CK Mapping

| Rule ID | Category | Severity | MITRE ATT&CK ID | Name | Monitored Vectors |
|---|---|---|---|---|---|
| `SQLI-001` | SQL Injection | **CRITICAL** | [T1190](https://attack.mitre.org/techniques/T1190/) | Union-Based SQLi | URI Path, Query, Referrer |
| `SQLI-002` | SQL Injection | **HIGH** | [T1190](https://attack.mitre.org/techniques/T1190/) | Boolean-Based SQLi | URI Path, Query, Referrer |
| `SQLI-003` | SQL Injection | **HIGH** | [T1190](https://attack.mitre.org/techniques/T1190/) | Time-Based Blind SQLi | URI Path, Query, Referrer |
| `SQLI-004` | SQL Injection | **HIGH** | [T1190](https://attack.mitre.org/techniques/T1190/) | Schema Enumeration | URI Path, Query, Referrer |
| `SQLI-005` | SQL Injection | **MEDIUM** | [T1190](https://attack.mitre.org/techniques/T1190/) | SQL Comments & Stacked Queries | URI Path, Query, Referrer |
| `TRAV-001` | Path Traversal | **HIGH** | [T1083](https://attack.mitre.org/techniques/T1083/) | Directory Climbing (`../`) | URI Path, Query |
| `TRAV-002` | Path Traversal | **CRITICAL** | [T1005](https://attack.mitre.org/techniques/T1005/) | Unix System File Disclosure | URI Path, Query |
| `TRAV-003` | Path Traversal | **CRITICAL** | [T1005](https://attack.mitre.org/techniques/T1005/) | Windows System File Disclosure | URI Path, Query |
| `SCAN-000` | Scanner Recon | **LOW** | [T1595](https://attack.mitre.org/techniques/T1595/) | Missing / Stripped User-Agent | User-Agent Header |
| `SCAN-001` | Scanner Recon | **HIGH** | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | SQLMap Tool Signature | User-Agent Header |
| `SCAN-002` | Scanner Recon | **HIGH** | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Web App Scanners (Nikto, Nessus) | User-Agent Header |
| `SCAN-003` | Scanner Recon | **MEDIUM** | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | Content Fuzzers (DirBuster, Gobuster) | User-Agent Header |
| `SCAN-004` | Scanner Recon | **MEDIUM** | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Probers (Nmap, Nuclei, Masscan) | User-Agent Header |
| `SCAN-005` | Scanner Recon | **HIGH** | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | CMS Exploiters (WPScan, Metasploit) | User-Agent Header |
| `BRUTE-001` | Brute-Force | **HIGH** | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Stuffing / Auth Bursts | HTTP Status, Endpoint, Time |
| `BURST-001` | Status Burst | **MEDIUM** | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | 4xx/5xx Fuzzing Anomaly Burst | HTTP Status, Time Window |

---

## 1. SQL Injection Rules (`rules/sqli.yaml`)

### Evasion Handling
The detector utilizes recursive multi-round URL decoding (`multi_url_decode`) before regex matching to neutralize evasion techniques including single URL encoding (`%20`), double encoding (`%2520`), and mixed-case keywords (`uNiOn sElEcT`).

### Payloads & Examples

#### `SQLI-001`: Union-Based SQL Injection
- **Pattern:** `(?i)(?:union\s+(?:all\s+)?select\s+)`
- **Matched Example:**
  ```http
  GET /products?category=books'%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1
  ```

#### `SQLI-002`: Boolean-Based SQL Injection
- **Pattern:** `(?i)(?:['"]\s*(?:or|and)\s*['"]?\w+['"]?\s*=\s*['"]?\w+['"]?|\b(?:or|and)\s+\d+=\d+|\b(?:or|and)\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"])`
- **Matched Example:**
  ```http
  GET /search?q=admin'%20OR%20'1'='1 HTTP/1.1
  ```

#### `SQLI-003`: Time-Based Blind SQL Injection
- **Pattern:** `(?i)(?:(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(\s*\d+)`
- **Matched Example:**
  ```http
  GET /api/items?id=1%20AND%20SLEEP(5) HTTP/1.1
  ```

#### `SQLI-004`: Database Schema Enumeration
- **Pattern:** `(?i)(?:information_schema\.(?:tables|columns|schemata)|sys\.tables|all_tab_columns)`
- **Matched Example:**
  ```http
  GET /catalog?filter=electronics'%20AND%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables)-- HTTP/1.1
  ```

---

## 2. Path Traversal Rules (`rules/traversal.yaml`)

### Evasion Handling
Normalizes standard directory delimiters (`/` and `\`), URL-encoded variants (`%2e%2e%2f`, `%2e%2e%5c`), and double-encoded variants (`%252e%252e%252f`).

### Payloads & Examples

#### `TRAV-001`: Directory Climbing
- **Pattern:** `(?:\.{2,}[/\\]|%2e%2e[/\\]|%2e%2e%2f|%2e%2e%5c|\.%2e[/\\]|%252e%252e%252f)`
- **Matched Example:**
  ```http
  GET /download?path=..%2f..%2f..%2fetc%2fshadow HTTP/1.1
  ```

#### `TRAV-002`: Unix System File Access
- **Pattern:** `(?i)(?:/etc/(?:passwd|shadow|group|hosts|issue|os-release)|/proc/(?:self|\d+)/(?:environ|cmdline|status)|/var/log/(?:auth|syslog|messages|nginx))`
- **Matched Example:**
  ```http
  GET /view?file=../../../../etc/passwd HTTP/1.1
  ```

#### `TRAV-003`: Windows System File Access
- **Pattern:** `(?i)(?:[a-z]:[/\\](?:windows|winnt)[/\\](?:win\.ini|system\.ini|repair[/\\]sam)|boot\.ini|web\.config)`
- **Matched Example:**
  ```http
  GET /read?file=C:\Windows\win.ini HTTP/1.1
  ```

---

## 3. Scanner Fingerprint Rules (`rules/scanner_ua.yaml`)

### Detection Logic
Inspects the `User-Agent` HTTP header for known vulnerability assessment tools, reconnaissance scanners, and automated fuzzers. Also checks for missing headers which automated scripts often strip.

### Tool Signatures Detected
- **`SCAN-001`**: `sqlmap` (Automated SQL injection exploitation tool)
- **`SCAN-002`**: `Nikto`, `OpenVAS`, `Nessus`, `Acunetix`, `Qualys`, `Arachni`, `W3AF`, `AppScan`
- **`SCAN-003`**: `DirBuster`, `Gobuster`, `ffuf`, `wfuzz`, `feroxbuster`, `dirb`
- **`SCAN-004`**: `Nmap Scripting Engine`, `Masscan`, `Zgrab`, `Nuclei`, `Shodan`, `Censys`
- **`SCAN-005`**: `WPScan`, `Joomscan`, `Droopescan`, `Metasploit`

---

## 4. Stateful Correlation Detectors

### `BRUTE-001`: Authentication Brute-Force & Credential Stuffing (`rules/bruteforce.yaml`)
- **Strategy:** Sliding time window per IP using `collections.deque`.
- **Target Endpoints:** `/login`, `/wp-login.php`, `/api/v1/auth`, `/admin/login`, `/oauth/token`, etc.
- **Monitored Status Codes:** `401`, `403`, `429` (and failed attempts returning 200).
- **Threshold:** >10 failed authentication attempts within a 60-second window.
- **State Cleanup:** Timestamps older than 60s are automatically evicted ($O(1)$ per entry).

### `BURST-001`: HTTP Status Anomaly Burst (`rules/status_burst.yaml`)
- **Strategy:** Sliding time window per IP monitoring rapid 4xx/5xx response generation.
- **Monitored Status Codes:** `400`, `401`, `403`, `404`, `500`, `502`, `503`.
- **Threshold:** >20 error responses within a 30-second window.
- **Use Case:** Detects fast content discovery fuzzers, API endpoint bruteforcing, and vulnerability probing.
