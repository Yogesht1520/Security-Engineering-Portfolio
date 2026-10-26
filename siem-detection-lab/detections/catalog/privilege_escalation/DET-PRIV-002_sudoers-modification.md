# Detection Specification: Sudoers Configuration Modification

| Field             | Value                                          |
|:------------------|:-----------------------------------------------|
| Detection ID      | DET-PRIV-002                                   |
| Wazuh Rule ID     | 100021, 100022                                 |
| Detection Name    | Sudoers File or Drop-in Directory Modified     |
| Data Source       | Wazuh File Integrity Monitoring (Syscheck)     |
| Decoder           | `syscheck` (built-in)                          |
| ATT&CK Technique  | T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| Severity          | Critical (level 12)                            |
| Logic             | FIM modification alert on `/etc/sudoers` (Rule 100021) or any file within `/etc/sudoers.d/` (Rule 100022) |
| FP Scenarios      | Authorized administrative update of sudo policies via configuration management (Ansible/Puppet) |
| Positive Tests    | Appending a line to `/etc/sudoers` or creating `/etc/sudoers.d/backdoor` |
| Negative Tests    | Modifications to `/etc/passwd` or `/etc/group` (should trigger generic FIM, not sudoers rule) |
| Response          | Review diff of file content immediately, identify session that modified sudoers, isolate if unauthorized |
| Status            | **Deployed & Verified**                        |
| Version           | 1.1                                            |

---

### Detection Rule Definition

```xml
<rule id="100021" level="12">
  <if_group>syscheck</if_group>
  <match>/etc/sudoers</match>
  <description>File integrity: Sudoers file (/etc/sudoers) modified - possible privilege escalation backdoor.</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>sudoers_modification,syscheck,</group>
</rule>

<rule id="100022" level="12">
  <if_group>syscheck</if_group>
  <match>/etc/sudoers.d/</match>
  <description>File integrity: Sudoers drop-in directory (/etc/sudoers.d/) modified - possible privilege escalation backdoor.</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>sudoers_modification,syscheck,</group>
</rule>
```
