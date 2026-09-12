# SOC Playbook: SSH Brute Force

**Triggered by:** Rule `100010` (SSH Brute Force) or Rule `100040` (Login After Brute Force)
**Associated MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts)

---

## 1. Initial Triage

1. **Identify the triggering rule:**
   - Did Rule `100040` (Login After Brute Force) fire? 
     - **YES:** Jump immediately to **Severity: CRITICAL**. This is an active compromise.
     - **NO:** Only `100010` fired. Proceed to step 2.
2. **Review the alert payload in Wazuh Dashboard:**
   - What is the Source IP (`data.srcip`)?
   - What usernames were targeted (`data.dstuser`)?
   - Over what time window did the attacks occur?

## 2. Validation & Enrichment

1. **Validate the Source IP:**
   - Query VirusTotal or AbuseIPDB with the Source IP. Is it a known scanner/malicious node?
   - Check the GeoIP data. Is the source country expected to access this system?
2. **Validate the Target Usernames:**
   - Are the targeted usernames valid accounts on the system? (e.g., `root`, `admin` vs. `company_employee`)
   - If valid accounts are targeted, the risk increases.
3. **Check for Success (Manual Verification):**
   - Query Wazuh for rule `5715` (sshd: authentication success) originating from the same IP or targeting the same user within the last hour, just in case the correlation rule missed it.

## 3. Scoping

Determine the extent of the activity:
- Has this IP attacked other hosts in the environment?
- Are other IPs participating in a coordinated brute-force attack (distributed brute force)?

## 4. Severity Assessment

| Criteria | Severity | Action |
|----------|----------|--------|
| Targeted invalid users, all failed | **Low** | Log and close. Internet background noise. |
| Targeted valid users, all failed | **Medium** | Consider blocking IP if persistent. |
| **Successful login observed** | **Critical** | Immediate containment required. |

## 5. Investigation (If Successful Login)

If a successful login occurred (`100040`):
1. **Identify actions taken post-compromise:**
   - Filter Wazuh events for the compromised host within the timeframe of the successful login.
   - Look for suspicious commands (Rule `100030`), user creation (Rule `100020`), or privilege escalation (Rule `100021`).
2. **Determine data exposure:**
   - What access does the compromised user have?
   - Was sensitive data accessed or exfiltrated?

## 6. Containment & Remediation

**Medium Severity (Persistent scanning):**
1. Add the Source IP to the external firewall blocklist or implement `fail2ban` on the host.

**Critical Severity (Successful Compromise):**
1. **Isolate:** Disconnect the affected host from the network immediately.
2. **Disable Account:** Disable the compromised user account across the environment.
3. **Reset Credentials:** Force password resets for the compromised user and revoke associated SSH keys.
4. **Rebuild (Honeypot specific):** Because the honeypot is disposable by design, destroy the VM and rebuild from the Terraform state.

## 7. Lessons Learned

- Did the alerts fire in a timely manner?
- Could the brute force have been prevented? (e.g., changing SSH port, using certificate-based auth, applying stricter firewall rules)
- Was the playbook effective in containing the incident?
