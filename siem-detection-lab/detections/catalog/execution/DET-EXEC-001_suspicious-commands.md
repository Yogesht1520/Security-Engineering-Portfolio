# Detection Specification: Suspicious Command Execution (Living Off The Land)

| Field             | Value                                          |
|:------------------|:-----------------------------------------------|
| Detection ID      | DET-EXEC-001                                   |
| Wazuh Rule ID     | 100030                                         |
| Detection Name    | Suspicious Reconnaissance / Exfiltration Tool Execution |
| Data Source       | Linux auditd `execve` events via Wazuh Agent   |
| Decoder           | `auditd` (built-in)                            |
| ATT&CK Technique  | T1059 — Command and Scripting Interpreter      |
| Severity          | Critical (level 12)                            |
| Logic             | Auditd `execve` event (base rule 80792) executing known dual-use networking or downloading binaries (`curl`, `wget`, `nc`, `ncat`, `netcat`, `socat`, `nmap`) |
| FP Scenarios      | Administrator manually troubleshooting network connectivity or downloading packages outside package manager |
| Positive Tests    | Executing `curl` or `nc` from an interactive shell on the honeypot |
| Negative Tests    | Executing benign commands like `ls`, `grep`, `cat` |
| Response          | Review process lineage (PPID), check destination network arguments, determine user session |
| Status            | **Deployed & Verified**                        |
| Version           | 1.1                                            |

---

### Detection Rule Definition

```xml
<rule id="100030" level="12">
  <if_sid>80792</if_sid> <!-- Base rule for auditd execve events -->
  <regex>exe="/usr/bin/wget"|exe="/usr/bin/curl"|exe="/bin/curl"|exe="/bin/wget"|exe="/usr/bin/nc"|exe="/bin/nc"|exe="/usr/bin/ncat"|exe="/usr/bin/netcat"|exe="/usr/bin/socat"|exe="/usr/bin/nmap"</regex>
  <description>Suspicious post-exploitation reconnaissance/exfiltration tool executed: $(exe).</description>
  <mitre>
    <id>T1059</id>
  </mitre>
  <group>living_off_the_land,</group>
</rule>
```
