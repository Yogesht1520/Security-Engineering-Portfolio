# Detection Specification: SSH Burst Brute Force

| Field             | Value                                          |
|:------------------|:-----------------------------------------------|
| Detection ID      | DET-SSH-001                                    |
| Wazuh Rule ID     | 100010                                         |
| Detection Name    | SSH Burst Brute Force                          |
| Data Source       | `/var/log/auth.log` via Wazuh Agent            |
| Decoder           | `sshd` (built-in)                              |
| ATT&CK Technique  | T1110.001 — Brute Force: Password Guessing     |
| Severity          | High (level 10)                                |
| Logic             | Chains on base brute-force (8+ authentication failures within 120s from the same source IP) |
| FP Scenarios      | Admin typo storm, misconfigured local script, automated key rotation |
| Positive Tests    | TC-002 (8 auth failures in 120s)               |
| Negative Tests    | TC-001 (7 auth failures in 120s)               |
| Response          | Investigate source IP, enrich via GeoIP/Reputation, block IP if persistent |
| Status            | **Deployed & Verified**                        |
| Version           | 1.1                                            |

---

### Detection Rule Definition

```xml
<rule id="100010" level="10">
  <if_sid>5712</if_sid> <!-- Base built-in rule: sshd brute force 8 failures in 120s -->
  <description>sshd: High-frequency burst brute-force attack detected from $(srcip).</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>authentication_failures,burst_bruteforce,</group>
</rule>
```

### Verification Evidence
Tested via `wazuh-logtest` on SIEM manager with 8 sequential failed attempts from `198.51.100.99`. Rule `100010` fires on attempt 8 with Level 10 and ATT&CK `T1110.001`.
