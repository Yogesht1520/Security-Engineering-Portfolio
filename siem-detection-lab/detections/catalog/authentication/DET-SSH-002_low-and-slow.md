# Detection Specification: Low-and-Slow SSH Brute Force

| Field             | Value                                          |
|:------------------|:-----------------------------------------------|
| Detection ID      | DET-SSH-002                                    |
| Wazuh Rule ID     | 100012                                         |
| Detection Name    | Low-and-Slow Persistent SSH Brute Force        |
| Data Source       | `/var/log/auth.log` via Wazuh Agent            |
| Decoder           | `sshd` (built-in)                              |
| ATT&CK Technique  | T1110.001 — Brute Force: Password Guessing     |
| Severity          | High (level 10)                                |
| Logic             | 5+ failed attempts from same source IP across a 1-hour window (3600 seconds) |
| FP Scenarios      | Intermittent user login mistakes across a work shift |
| Positive Tests    | TC-006 (5 failures across 3600s from single IP) |
| Negative Tests    | 4 failures across 3600s                        |
| Response          | Review target user accounts, correlate with IP reputation feeds |
| Status            | **Deployed & Verified**                        |
| Version           | 1.1                                            |

---

### Detection Rule Definition

```xml
<rule id="100012" level="10" frequency="5" timeframe="3600">
  <if_matched_group>authentication_failed</if_matched_group>
  <same_source_ip />
  <description>sshd: Low-and-slow persistent brute-force attack detected from $(srcip).</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>authentication_failures,low_and_slow,</group>
</rule>
```
