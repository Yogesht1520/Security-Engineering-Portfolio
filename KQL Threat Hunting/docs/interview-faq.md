# Top 10 Technical Interview Questions: Microsoft Defender XDR, Sentinel & KQL

**Author:** Yogesh Thakur  
**Audience:** Security Engineers, Detection Engineers, Lead Threat Hunters, SOC Analysts

---

### Q1: How does KQL partition pruning work, and why must filter conditions come first?
**Answer:**  
In Azure Data Explorer (ADX), Microsoft Sentinel, and Defender XDR, data is stored in immutable compressed horizontal shards known as **extents**. Each extent has metadata recording its minimum and maximum timestamp (`MinUtcTime` and `MaxUtcTime`).  
When a query starts with `where TimeGenerated > ago(7d)` or `Timestamp > ago(24h)`, the Kusto query planner inspects extent metadata and completely skips reading any extent files outside the requested window. This is known as **extent pruning** or **partition pruning**. If you place transformations, string operations, or `summarize` before the time filter, Kusto may have to decompress and process petabytes of irrelevant data across the cluster, leading to CPU throttling, high query costs, and timeouts.

---

### Q2: What is the difference between `has` and `contains` in KQL, and why does it matter?
**Answer:**  
- `has` is an **indexed token match**. Kusto tokenizes text into alphanumeric words of 3+ characters. When you write `where CommandLine has "powershell"`, Kusto performs a direct binary lookup against the inverted index, resulting in sub-millisecond execution.
- `contains` is an **unindexed substring search** equivalent to `LIKE '%powershell%'` in SQL. It bypasses the inverted index and scans every single byte in the column.
- **Rule of Thumb:** Always use `has` or `has_any` when searching for whole words, process names, or arguments. Only resort to `contains` if you are matching arbitrary substrings (e.g. searching for a partial GUID or URL parameter) where indexing does not apply.

---

### Q3: How do you perform stateful, row-to-row window calculations in KQL without self-joins?
**Answer:**  
In traditional SQL or basic SIEMs, calculating the time difference between consecutive events requires an expensive self-join ($O(N^2)$ complexity).  
In KQL, you use the `serialize` operator combined with `prev()` or `next()`. Once data is sorted (`sort by Host asc, Timestamp asc`), `serialize` instructs the Kusto execution engine to treat the row stream as strictly ordered. Calling `prev(Timestamp)` accesses the timestamp from the preceding row, allowing $O(N)$ linear-time evaluation of inter-arrival deltas (e.g., detecting periodic C2 beaconing or rapid brute force intervals).

---

### Q4: Explain the difference between Sentinel's `SigninLogs` and Defender's `DeviceLogonEvents`.
**Answer:**  
- `SigninLogs` captures **cloud identity authentication** to Microsoft Entra ID (Azure AD), such as an interactive user logging into Office 365, Azure Portal, or cloud SaaS apps. It tracks Conditional Access status, client IP, Entra ID Protection risk signals, and MFA results.
- `DeviceLogonEvents` captures **endpoint OS-level logons** monitored by the Defender for Endpoint sensor (Windows Event ID 4624/4625 equivalent). It tracks local interactive logons (Type 2), network logons (Type 3), Remote Desktop RDP (Type 10), and service logons (Type 5).
- **Correlation value:** An attacker logging in with compromised credentials in `SigninLogs` followed immediately by a Type 10 or Type 3 logon in `DeviceLogonEvents` reveals cloud-to-on-premises lateral compromise.

---

### Q5: How do you mitigate false positives in password spray detections?
**Answer:**  
Standard password spray hunts look for a single IP attempting logons across many distinct accounts with failures (e.g. `ResultType == "50126"`).  
**Common False Positives:**
1. Enterprise VPN concentrators or NAT gateways aggregating hundreds of users behind a single public IP.
2. Legacy email clients (ActiveSync / IMAP) retrying cached expired passwords.
**Tuning Strategy:**
- Exclude known corporate egress ranges and VPN public IPs using dynamic lookup lists or `ipv4_is_private()`.
- Filter out single accounts that fail 50 times (which is brute-force, not a spray) by requiring a high ratio of `DistinctUsers / TotalAttempts`.
- Require `ResultType != "0"` across $N$ distinct user accounts, followed by a subsequent successful login (`ResultType == "0"`) to focus high-severity triage on successful penetrations.

---

### Q6: How does Kusto handle dynamic/JSON data, and what is the performance impact?
**Answer:**  
Columns typed as `dynamic` (such as `AdditionalFields` in Defender or `LocationDetails` in Sentinel) store structured or semi-structured JSON objects.  
- Individual fields can be accessed using dot notation (`AdditionalFields.ConsumerName`) or bracket notation (`Properties["resource"]`).
- In terms of performance, repeatedly accessing dynamic properties in large `where` filters forces Kusto to decompress and parse the JSON blob for every row.
- **Optimization:** Filter on statically typed native columns (`ActionType`, `FileName`, `TimeGenerated`) *before* parsing dynamic properties, and use `tostring(dynamic_col.prop)` or `extend` only on the filtered candidate rows.

---

### Q7: What are the three essential detection angles for human-operated ransomware before encryption?
**Answer:**  
1. **Inhibit System Recovery (T1490):** Deletion of Volume Shadow Copies (`vssadmin delete shadows`, `wmic shadowcopy delete`) and tampering with boot configuration (`bcdedit /set {default} recoveryenabled no`).
2. **Security Tool Tampering (T1562.001):** Disabling Defender Antivirus real-time monitoring via PowerShell (`Set-MpPreference -DisableRealtimeMonitoring $true`) or adding root directory exclusions (`Add-MpPreference -ExclusionPath "C:\"`).
3. **Mass Storage & Share Enumeration:** Rapid discovery of domain SMB shares (`net view`, `Get-SmbShare`) and querying Active Directory for backup servers.

---

### Q8: What is the purpose of `arg_max()` and `arg_min()` in KQL?
**Answer:**  
`arg_max(ExprToMaximize, * | ExprToReturn)` is an aggregation function that returns the row where `ExprToMaximize` is maximized.  
- It is commonly used for deduplication: e.g., finding the latest configuration or status for each machine:
  ```kql
  DeviceInfo
  | summarize arg_max(Timestamp, OSPlatform, OSBuild) by DeviceId
  ```
- Unlike `max()`, which only returns the scalar maximum value of a single column, `arg_max()` preserves the entire row context associated with that maximum value, eliminating the need for costly self-joins.

---

### Q9: How do you prevent KQL queries from hitting memory limits (E_MEMORY_LIMIT_EXCEEDED)?
**Answer:**  
1. **Prune Early:** Apply `where TimeGenerated > ago(...)` on the first line.
2. **Project Early:** Use `project` or `project-away` immediately after table ingestion so unused wide columns (like raw event blobs or lengthy paths) do not consume cache memory during pipeline stages.
3. **Limit High-Cardinality Joins:** Avoid joining two massive tables without prior filtering. When joining, specify the smaller table on the left or use `kind=innerunique` / `kind=leftouter`.
4. **Cap Make-Set/Make-List:** When using `make_set(Column)`, always pass a maximum element limit (e.g. `make_set(IPAddress, 100)`) to prevent unbounded array expansion.

---

### Q10: How do you design Detection-as-Code for Microsoft Sentinel in an enterprise CI/CD pipeline?
**Answer:**  
1. **Source of Truth:** Hunts are authored as version-controlled code artifacts (YAML metadata + `.kql` query files).
2. **Static Analysis & Semantic Verification:** A CI workflow (GitHub Actions) parses each query into an AST using Microsoft's language service, validating table names, column existence, and scalar functions against target workspace schemas.
3. **Automated Testing:** Queries are evaluated against deterministic synthetic attack telemetry and benign baseline datasets to ensure positive detection and zero false positives.
4. **Continuous Deployment:** On merge to `main`, an exporter pipeline converts the tested YAML/KQL into Azure Resource Manager (ARM) / Bicep templates and deploys them to Sentinel workspaces using the Microsoft Sentinel REST API.

