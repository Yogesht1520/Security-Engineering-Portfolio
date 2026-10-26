# Detection Specification: Successful SSH Login Following Brute-Force Attack

| Field             | Value                                          |
|:------------------|:-----------------------------------------------|
| Detection ID      | DET-SSH-004                                    |
| Wazuh Rule ID     | 100040, 100041                                 |
| Detection Name    | SSH Authentication Success After Brute Force Attack |
| Data Source       | `/var/log/auth.log` via Wazuh Agent            |
| Decoder           | `sshd` (built-in)                              |
| ATT&CK Technique  | T1110.001 (Password Guessing) & T1078 (Valid Accounts) |
| Severity          | Critical (level 14)                            |
| Logic             | Successful login (Rule 5715) from the same source IP that triggered Rule 100010 (within 600s) or Rule 100012 (within 3600s) |
| FP Scenarios      | Administrator forgotten password who guessed correctly after multiple failed attempts |
| Positive Tests    | TC-003 (8 failed logins from IP A followed immediately by successful login from IP A) |
| Negative Tests    | TC-004 (8 failed logins from IP A followed by successful login from IP B — no alert) |
| Response          | **SEV-1 Incident**: Immediate host isolation, session termination, credential reset, and evidence preservation |
| Status            | **Deployed & Verified**                        |
| Version           | 1.1                                            |

---

### Detection Rule Definition

```xml
<rule id="100040" level="14" timeframe="600">
  <if_matched_sid>100010</if_matched_sid> <!-- Base rule: Burst brute-force detected -->
  <if_sid>5715</if_sid> <!-- Base rule: sshd authentication success -->
  <same_source_ip />
  <description>sshd: CRITICAL - Successful login following burst brute-force attack from $(srcip).</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1078</id>
  </mitre>
  <group>authentication_success,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_11.4,</group>
</rule>
```

### Verification Evidence
Tested via `wazuh-logtest` on SIEM manager with 8 failed attempts from `198.51.100.99` followed by an accepted publickey/password from `198.51.100.99`. Rule `100040` fired with Severity 14.
