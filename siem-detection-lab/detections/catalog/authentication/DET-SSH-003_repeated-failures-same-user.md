# Detection Specification: Repeated Authentication Failures Targeting Same User

| Field             | Value                                          |
|:------------------|:-----------------------------------------------|
| Detection ID      | DET-SSH-003                                    |
| Wazuh Rule ID     | 100014                                         |
| Detection Name    | Repeated Authentication Failures Targeting Same User |
| Data Source       | `/var/log/auth.log` via Wazuh Agent            |
| Decoder           | `sshd` (built-in)                              |
| ATT&CK Technique  | T1110.003 — Password Spraying                  |
| Severity          | High (level 11)                                |
| Logic             | 8+ failed authentication attempts targeting the same username (`dstuser`) within 300 seconds |
| Clarification Note| Renamed from "Distributed Spray" to accurately represent account-level targeting until multi-IP diversity correlation script is deployed |
| FP Scenarios      | Automated batch script attempting scheduled sync with expired service account password |
| Positive Tests    | TC-007 (8 failed attempts targeting user `admin` within 300s) |
| Negative Tests    | TC-008 (Attempts spread across multiple usernames) |
| Response          | Check account status, verify whether password lockouts are triggered |
| Status            | **Deployed & Verified**                        |
| Version           | 1.1                                            |

---

### Detection Rule Definition

```xml
<rule id="100014" level="11" frequency="8" timeframe="300">
  <if_matched_group>authentication_failed</if_matched_group>
  <same_user />
  <description>sshd: High-frequency authentication failures targeting user account '$(dstuser)'.</description>
  <mitre>
    <id>T1110.003</id>
  </mitre>
  <group>authentication_failures,password_spray,</group>
</rule>
```
