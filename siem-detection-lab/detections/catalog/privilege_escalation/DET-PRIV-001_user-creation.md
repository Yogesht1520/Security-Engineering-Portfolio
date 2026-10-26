# Detection Specification: Unauthorized User Account Creation

| Field             | Value                                          |
|:------------------|:-----------------------------------------------|
| Detection ID      | DET-PRIV-001                                   |
| Wazuh Rule ID     | 100020                                         |
| Detection Name    | Local User Account Creation                    |
| Data Source       | Linux auditd / `/var/log/audit/audit.log` via Wazuh Agent |
| Decoder           | `auditd` (built-in)                            |
| ATT&CK Technique  | T1136.001 — Create Account: Local Account      |
| Severity          | High (level 8)                                 |
| Logic             | Chains on base rule 5902 (`useradd` command execution detected via auditd) |
| FP Scenarios      | Authorized system administrator provisioning a legitimate service or user account |
| Positive Tests    | Running `useradd` on the monitored host        |
| Negative Tests    | Existing user login or benign command execution |
| Response          | Validate change ticket, determine parent process and user who invoked `useradd` |
| Status            | **Deployed & Verified**                        |
| Version           | 1.1                                            |

---

### Detection Rule Definition

```xml
<rule id="100020" level="8">
  <if_sid>5902</if_sid> <!-- Base rule: useradd command executed -->
  <description>System administration: New user account created.</description>
  <mitre>
    <id>T1136.001</id>
  </mitre>
  <group>account_creation,</group>
</rule>
```
