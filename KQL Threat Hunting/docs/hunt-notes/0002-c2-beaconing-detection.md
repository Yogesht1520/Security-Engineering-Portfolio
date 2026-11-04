# Hunt Note 0002: Command and Control Periodic Beaconing Detection

**Hunt ID:** HB-C2-001  
**Technique:** MITRE ATT&CK T1071 (Application Layer Protocol)  
**Platform:** Microsoft Defender for Endpoint / Defender XDR (`DeviceNetworkEvents`)  
**Author:** Yogesh Thakur (Detection Engineering Lead)

---

## 1. Executive Summary & Threat Model

Post-exploitation frameworks such as **Cobalt Strike**, **Sliver**, **Mythic**, and **Brute Ratel** rely on periodic network callbacks ("beacons") from the compromised host to external Command-and-Control (C2) infrastructure.

Adversaries configure their implants with:
- **Sleep interval:** A base time period between heartbeats (e.g. 60 seconds, 300 seconds).
- **Jitter:** A percentage variation applied to randomize the interval and evade static threshold-based anomaly detection (e.g. 10% or 20% jitter).

Traditional perimeter firewalls and basic SIEM rules fail because simple request counting alerts on benign applications that poll regularly (such as Spotify, Microsoft Teams status checks, or NTP). To reliably catch C2 heartbeats without flooding analysts with false alarms, we must measure the **regularity of connection intervals** using statistical dispersion.

---

## 2. KQL Mechanics & Statistical Theory

### The Coefficient of Variation (Jitter Ratio)

Given a sequence of connection timestamps $\{t_1, t_2, \dots, t_n\}$ to the same `(RemoteIP, RemotePort)`:

1. **Inter-Arrival Time (Delta):**
   $$\Delta t_i = t_i - t_{i-1}$$
2. **Mean Delta ($\mu$):**
   $$\mu = \frac{1}{n-1} \sum_{i=2}^n \Delta t_i$$
3. **Standard Deviation ($\sigma$):**
   $$\sigma = \sqrt{\frac{1}{n-1} \sum_{i=2}^n (\Delta t_i - \mu)^2}$$
4. **Coefficient of Variation ($CV$ or Jitter Ratio):**
   $$CV = \frac{\sigma}{\mu}$$

- **Human browsing / Benign bursty web traffic:** $CV > 0.8$ (empirically observed high variation across baseline telemetry).
- **Automated C2 beacon with low/medium jitter:** $CV \le 0.35$ (experimental heuristic threshold calibrated against synthetic beaconing datasets).

> [!NOTE]
> Jitter ratio thresholds ($0.35$ vs $0.80$) are **experimental heuristic parameters**, not universal physical constants. In enterprise environments, they must be baseline-calibrated against specific corporate proxy and endpoint application profiles to avoid false-positive alert bursts.

---

## 3. Pure KQL Implementation Without External Libraries

In SQL or basic Log Analytics, calculating row-to-previous-row deltas requires costly self-joins. KQL provides the native `serialize` and `prev()` window operators, allowing in-memory, linear-time streaming evaluation:

```kql
let lookback = 24h;
let minConnections = 15;
let maxJitterRatio = 0.35;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| sort by DeviceName asc, InitiatingProcessFileName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| serialize
| extend PrevDevice = prev(DeviceName),
         PrevProc = prev(InitiatingProcessFileName),
         PrevIP = prev(RemoteIP),
         PrevPort = prev(RemotePort),
         PrevTime = prev(Timestamp)
| extend TimeDelta = datetime_diff('second', Timestamp, PrevTime)
| where DeviceName == PrevDevice 
    and InitiatingProcessFileName == PrevProc 
    and RemoteIP == PrevIP 
    and RemotePort == PrevPort 
    and TimeDelta > 0
| summarize 
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    TotalConnections = count(),
    AvgDelta = avg(TimeDelta),
    StdDevDelta = stdev(TimeDelta),
    MinDelta = min(TimeDelta),
    MaxDelta = max(TimeDelta),
    RemoteUrls = make_set(RemoteUrl, 3)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where TotalConnections >= minConnections
| extend JitterRatio = iff(AvgDelta > 0, round(StdDevDelta / AvgDelta, 3), 1.0)
| where JitterRatio <= maxJitterRatio
| project FirstSeen, LastSeen, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrls,
          TotalConnections, AvgDelta, StdDevDelta, JitterRatio
| order by JitterRatio asc, TotalConnections desc
```

### Why Line 1 Matters (Performance Architecture)
- `where Timestamp > ago(lookback)` partition-prunes the cluster so petabytes of historical logs are never scanned.
- `not(ipv4_is_private(RemoteIP))` strips all internal lateral SMB/RPC/DNS chatter upfront, cutting pipeline row volume by ~85%.
- `sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc` establishes the strict grouping required by `serialize`.

---

## 4. SOC Analyst Triage Playbook

When this hunt produces a hit:

1. **Process Provenance Verification:**
   - Look at `Processes`. Is it `rundll32.exe`, `powershell.exe`, `svchost.exe`, or an unsigned binary in `C:\Users\*\AppData\Local\Temp`?
   - If `svchost.exe` is making external connections without a matching Windows service name, inspect for process hollowing or DLL injection.
2. **Destination Reputation:**
   - Check `RemoteIP` against VirusTotal, AlienVault OTX, and GreyNoise.
   - Look up WHOIS registration date: newly registered domains (< 30 days) hosting port 443/8443 are high-confidence indicators of rogue C2 redirectors.
3. **Host Memory & EDR Correlation:**
   - Check `DeviceProcessEvents` and `DeviceFileEvents` on `DeviceName` in the 30 minutes preceding `FirstSeen`.
   - Look for initial access vectors: phishing document opened (`WINWORD.EXE`), macro execution, or LOLBin download (`certutil.exe -urlcache`).

---

## 5. False Positive Management & Tuning

| Benign Pattern | Root Cause | Tuning Solution |
| :--- | :--- | :--- |
| **Microsoft 365 Telemetry** | Teams, OneDrive polling push notification endpoints | Filter known Microsoft FQDN suffixes (`*.office.com`, `*.microsoft.com`) |
| **Enterprise EDR / Antivirus** | Cloud reputation lookup agents | Filter trusted vendor IPs or signed agent processes |
| **Streaming / WebSockets** | Audio/Video streams maintaining keepalive ping | Require `TotalConnections >= 20` and filter standard CDN CIDRs |

