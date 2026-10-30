# SIEM Lab — Lifecycle Operations & Safe Restart Guide

**Document Version:** 2.0  
**Scope:** Provisioning, Configuration, Automated Testing, Evidence Preservation, and Safe Teardown.  

---

## 1. Prerequisites & Pre-Flight Checks

Before provisioning or restarting the lab, ensure your local operator environment is aligned:

### 1.1 Verify Operator Public IP
The SIEM management plane (SSH on TCP 22 and Dashboard on TCP 443) is strictly whitelisted to your public IP.
```powershell
# In PowerShell / Bash: Check your current public IP
curl -s https://ifconfig.me/ip
```
Update `infra/terraform/terraform.tfvars` if your IP has changed:
```hcl
your_public_ip = "YOUR_CURRENT_IP/32"
```

### 1.2 Verify SSH Key & Google Cloud Credentials
```bash
# Verify SSH keypair exists
ls -l ~/.ssh/siem_lab_key

# Verify GCP authentication
gcloud auth list
```

---

## 2. Infrastructure Provisioning (Terraform)

Provision the hardened VPC, firewall rules, and virtual machines:

```bash
cd infra/terraform
terraform init
terraform fmt -check
terraform validate
terraform apply -auto-approve
```

**Terraform provisions 3-Tier Hardened Architecture:**
- Tier 1 (DMZ Subnet `10.0.10.0/24`): `siem-lab-honeypot` (Private IP `10.0.10.2`, Public Honeypot IP)
- Tier 2 (SIEM Core Subnet `10.0.20.0/24`): `siem-lab-wazuh` (Private IP `10.0.20.2`, No Public IP)
- Tier 3 (Admin Management Subnet `10.0.30.0/24`): `siem-lab-bastion` (Private IP `10.0.30.2`, Bastion Public IP)
- Firewalls: Egress default-deny (`priority 65534`) on honeypot, package updates allow (`priority 1110`), Wazuh agent telemetry (`priority 1000`), OpenSearch public deny (`priority 800`).

---

## 3. Wazuh SIEM Stack Installation

SSH into the SIEM VM through the Admin Bastion jumpbox (SIEM has no public IP):
```bash
# Connect via Bastion Jumpbox ProxyJump
ssh -i ~/.ssh/siem_lab_key -J ubuntu@<BASTION_PUBLIC_IP> ubuntu@10.0.20.2
```

Install Wazuh 4.9.2 All-in-One:
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
> [!IMPORTANT]
> Save the admin password printed upon installation completion. It is also stored in `/home/ubuntu/wazuh-install-files/wazuh-passwords.txt`.

---

## 4. Honeypot Agent Bootstrap & Pinned Enrollment

SSH into the Honeypot VM:
```bash
ssh -i ~/.ssh/siem_lab_key ubuntu@<HONEYPOT_PUBLIC_IP>
```

Execute the bootstrap script:
```bash
chmod +x setup_honeypot.sh
sudo ./setup_honeypot.sh
```

### Critical Package Pinning
Wazuh Manager 4.9.2 strictly rejects connections from higher agent versions (e.g., 4.14.x). The bootstrap script automatically pins the agent package:
```bash
sudo apt-get install -y wazuh-agent=4.9.2-1
sudo apt-mark hold wazuh-agent
```

Enroll the agent against the private SIEM manager IP:
```bash
sudo /var/ossec/bin/agent-auth -m 10.0.20.2 -A siem-lab-honeypot
sudo systemctl restart wazuh-agent
```

---

## 5. Deploy & Validate Custom Detection Rules

From your local machine or repository root, deploy the custom detection rules to the SIEM manager:

```bash
# Verify static rule syntax locally first
python tests/validate_rules.py

# Push custom rules to SIEM manager (via Bastion jumpbox)
scp -i ~/.ssh/siem_lab_key -o "ProxyJump=ubuntu@<BASTION_PUBLIC_IP>" wazuh/custom_rules/*.xml ubuntu@10.0.20.2:/tmp/

# On SIEM Manager: Install and verify syntax
ssh -i ~/.ssh/siem_lab_key -J ubuntu@<BASTION_PUBLIC_IP> ubuntu@10.0.20.2 "
  sudo cp /tmp/*.xml /var/ossec/etc/rules/
  sudo chown wazuh:wazuh /var/ossec/etc/rules/*.xml
  sudo /var/ossec/bin/wazuh-analysisd -t
  sudo systemctl restart wazuh-manager
"
```

---

## 6. Automated Testing & Verification

Run the automated test harnesses to confirm full detection engine functionality:

```bash
# 1. Run local security and file leak audits
python tests/security_scan.py

# 2. Run rule unit tests against wazuh-logtest on SIEM Manager
bash tests/unit/run_rule_unit_tests.sh

# 3. (Optional) Run synthetic event injection on Honeypot
ssh -i ~/.ssh/siem_lab_key ubuntu@<HONEYPOT_PUBLIC_IP> "bash /home/ubuntu/validate_detections.sh --inject-only"
```

---

## 7. Operational Dashboards

### 7.1 Import OpenSearch Dashboards
Automatically import the customized SOC operational dashboards into the live Wazuh UI:
```bash
# Option 1: Via local SSH port-forward tunnel through Bastion (https://localhost:8443)
bash wazuh/dashboards/import_dashboards.sh localhost:8443 <WAZUH_PASSWORD>

# Option 2: Directly from Admin Bastion jumpbox to internal SIEM manager IP
bash wazuh/dashboards/import_dashboards.sh 10.0.20.2 <WAZUH_PASSWORD>
```
Access the dashboards locally via SSH tunnel: `https://localhost:8443` (execute `terraform output -raw wazuh_dashboard_tunnel` to open the tunnel).

### 7.2 Standalone Interactive SOC Visualizer
Open [dashboards/index.html](file:///c:/Users/yoges/Documents/Security-Engineering-Portfolio/siem-detection-lab/dashboards/index.html) in any modern browser to view interactive KPIs, MITRE ATT&CK charts, live alert feeds, and case records without needing active cloud instances.

---

## 8. Safe Teardown & Mandatory Evidence Preservation

> [!CAUTION]
> **MANDATORY SAFETY REQUIREMENT:**  
> Never run `terraform destroy` without first running `preserve_evidence.sh`. Destroying instances before capturing telemetry forfeits real attack evidence, audit logs, and forensic artifacts.

### Step 1: Preserve Forensic Evidence Bundle
```bash
# Executes forensic snapshotting and SHA-256 integrity hashing
bash incident_management/response/preserve_evidence.sh
```
Artifacts will be securely captured in `evidence/<TIMESTAMP>/` containing:
- Raw `honeypot_auth.log`
- Kernel `honeypot_audit.log`
- Volatile sockets and routing (`honeypot_system_state.txt`)
- Normalized Wazuh alerts (`wazuh_alerts.json`)
- Cryptographic hash manifest (`SHA256SUMS.txt`)

### Step 2: Teardown Cloud Infrastructure
Once evidence preservation completes with `[+] Evidence preservation complete`:
```bash
cd infra/terraform
terraform destroy -auto-approve
```
All GCP virtual machines, static IP allocations, and firewall rules are cleanly decommissioned, preventing unwanted cloud charges.
