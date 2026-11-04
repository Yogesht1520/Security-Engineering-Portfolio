# Hunt Note 0003: Ransomware Inhibiting System Recovery

**Hunt IDs:** HB-RW-001 (Shadow Copy Deletion), HB-RW-002 (Mass File Rename), HB-RW-003 (Bcdedit Tampering)  
**Technique:** MITRE ATT&CK T1490 (Inhibit System Recovery) & T1486 (Data Encrypted for Impact)  
**Platform:** Microsoft Defender XDR (`DeviceProcessEvents`, `DeviceFileEvents`)  
**Author:** Yogesh Thakur (Detection Engineering Lead)

---

## 1. Attack Lifecycle & Precursor Detection

Human-operated ransomware (such as LockBit 3.0, BlackCat/ALPHV, Conti, and Akira) follows a predictable final stage execution chain before detonating the payload:

```
[ Compromise / Credential Dumping ]
               │
               ▼
   [ Inhibit System Recovery ]   <── HB-RW-001 & HB-RW-003 (DETECT HERE)
   • Delete Volume Shadow Copies (vssadmin / wmic)
   • Disable Windows Error Recovery (bcdedit)
   • Stop Antivirus & Backup Services (sc stop, net stop)
               │
               ▼
     [ Mass Data Encryption ]   <── HB-RW-002 (LAST RESORT MITIGATION)
   • Iterate local disks & SMB shares
   • Append extension (.lockbit, .crypted)
   • Drop ransom note (README.txt)
```

The SOC's highest ROI is catching the adversary **during the recovery inhibition phase**—before mass encryption begins.

---

## 2. Technical Anatomy of Recovery Tampering Commands

Adversaries disable OS backup snapshots and boot recovery so victims cannot roll back changes:

### 1. Volume Shadow Copy Destruction (HB-RW-001)
```cmd
vssadmin.exe delete shadows /all /quiet
wmic.exe shadowcopy delete /nointeractive
wbadmin.exe delete catalog -quiet
```
- **KQL Defense:** In Defender XDR, monitoring `DeviceProcessEvents` where `FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe")` combined with switches `delete` and `shadows`.

### 2. Boot Configuration Data Tampering (HB-RW-003)
```cmd
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
```
- **KQL Defense:** Monitoring `ProcessCommandLine has_any ("recoveryenabled", "bootstatuspolicy", "ignoreallfailures")`.

### 3. Safe-Mode Persistence / Weaponization
```cmd
bcdedit.exe /set {current} safeboot minimal
```
- Adversaries force a reboot into Safe Mode where third-party EDR kernel drivers and endpoint sensors may fail to initialize, giving the ransomware unhindered encryption capability.

---

## 3. High-Performance KQL Hunting Logic

```kql
// Detects bcdedit boot configuration tampering
let lookback = 7d;
let recoveryTamperingArgs = dynamic([
    "recoveryenabled", "bootstatuspolicy", "ignoreallfailures", "safeboot"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName =~ "bcdedit.exe" or ProcessCommandLine has "bcdedit"
| where ProcessCommandLine has_any (recoveryTamperingArgs)
| extend TamperedFeature = case(
    ProcessCommandLine has "recoveryenabled", "Recovery Disabled",
    ProcessCommandLine has "bootstatuspolicy", "Failure Policy Tampered",
    ProcessCommandLine has "safeboot", "SafeBoot Modified",
    "Other Boot Config Change"
)
| project Timestamp, DeviceName, TamperedFeature, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, AccountName, ProcessIntegrityLevel
| order by Timestamp desc
```

### Performance Optimization:
1. `where Timestamp > ago(lookback)` ensures partition pruning in Kusto.
2. `FileName =~ "bcdedit.exe"` uses case-insensitive exact string match before parsing the broader command line.
3. `extend TamperedFeature = case(...)` categorizes alerts for fast SOC prioritization without repetitive regex operations.

---

## 4. Triage & Incident Response Protocol

If this hunt triggers:

1. **Immediate Host Network Isolation:**
   - Execute Defender for Endpoint API action: `IsolateDevice`.
   - Prevent lateral spread over SMB (port 445) or RDP (port 3389).
2. **Parent Process Investigation:**
   - Check `InitiatingProcessCommandLine`. Is it an interactive administrative CMD/PowerShell session, a scheduled task, or a PsExec remote service?
   - If spawned by `services.exe` or `wsmprovhost.exe`, the adversary is executing remotely from another compromised host.
3. **Rollback & Verification:**
   - Restore default Windows boot policies:
     ```cmd
     bcdedit /set {default} recoveryenabled yes
     bcdedit /set {default} bootstatuspolicy displayallfailures
     ```
   - Verify backup volume integrity using off-line, immutable cloud backups.

