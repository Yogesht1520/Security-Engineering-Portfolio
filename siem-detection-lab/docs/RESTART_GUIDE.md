# SIEM Lab — Lifecycle Operations & Safe Restart Guide

**Document Version:** 2.0  
**Scope:** Provisioning, Configuration, Automated Testing, Evidence Preservation, and Safe Teardown.  

---

## 1. Prerequisites & Pre-Flight Checks

Before provisioning or restarting the lab, ensure your local operator environment is aligned:

### 1.1 Standardized Zero-Trust Access Architecture
The lab strictly adheres to a **Zero-Trust Management Access Architecture**:
- **Supported Management Access (Standard):** All administrative access to Bastion (`siem-lab-bastion`) and SIEM Manager (`siem-lab-wazuh`) routes exclusively through **Google Cloud Identity-Aware Proxy (IAP) TCP Forwarding** with **Google Cloud OS Login and multi-factor authentication (MFA)**. No direct public SSH or management ports are exposed to the open internet.
- **Defense-in-Depth IP Whitelisting:** `your_public_ip` in `infra/terraform/terraform.tfvars` provides a secondary network-level firewall boundary on the Bastion ingress rule to restrict any direct management traffic strictly to your workstation IP (`YOUR_IP/32`).

```powershell
# In PowerShell / Bash: Verify your current workstation public IP
curl -s https://ifconfig.me/ip
```
Ensure `infra/terraform/terraform.tfvars` contains your current workstation IP:
```hcl
your_public_ip = "YOUR_CURRENT_IP/32"
```

### 1.2 Access Model Prerequisites (OS Login vs. Honeypot Key)

The lab enforces strict separation between the management plane and the untrusted threat zone:
1. **Management Plane (Bastion & SIEM VMs):**
   - **Authentication:** Google Cloud IAM identity authenticated via `gcloud auth login`.
   - **Prerequisite IAM Roles:**
     - `roles/compute.osAdminLogin` (or `roles/compute.osLogin`)
     - `roles/iap.tunnelResourceAccessor`
   - **Multi-Factor Authentication (MFA):** Enforced by Cloud Identity / Google Workspace context-aware access policies.
   - **Zero Static Keys:** Static SSH keys are blocked (`block-project-ssh-keys = "TRUE"`).
2. **Honeypot VM (DMZ Tier):**
   - **Authentication:** Uses an **isolated instance SSH keypair** (`~/.ssh/siem_lab_key`) and intentionally does *not* enable OS Login or IAP.
   - **Service Account Isolation:** Attached to a dedicated zero-privilege service account (`siem-lab-honeypot-sa`) with zero IAM roles.
   - **Boundary Guarantee:** Attacker probes on the honeypot have zero pathway into Google Cloud IAM or management planes.

```bash
# 1. Verify GCP CLI authentication for OS Login
gcloud auth list

# 2. Verify isolated SSH keypair exists for Honeypot ingestion
ls -l ~/.ssh/siem_lab_key

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

Access the management plane using Google Cloud IAM OS Login via Identity-Aware Proxy (IAP) with MFA enforcement.

**Supported Access Pathways:**
- **Primary (Workstation-Direct IAP Tunnel — Recommended):**
  Connect directly from your local workstation to the private SIEM Manager via Google Cloud IAP. This zero-reauthentication pathway completely eliminates the need to store, cache, or forward operator credentials through intermediate jumpbox VMs:
  ```bash
  gcloud compute ssh siem-lab-wazuh --zone=us-central1-a --tunnel-through-iap
  ```
- **Segmented Management (Admin Bastion Jumpbox):**
  For administrative workflows requiring origin from within the isolated Admin Subnet (`10.0.30.0/24`):
  ```bash
  # Step A: SSH into Admin Bastion via IAP Tunnel with SSH Agent Forwarding
  gcloud compute ssh siem-lab-bastion --zone=us-central1-a --tunnel-through-iap --ssh-flag="-A"

  # Step B: From Bastion, connect to the internal SIEM Manager over VPC private network
  # Identity & Permission Propagation:
  # - Option 1 (SSH Agent Forwarding): Your local OS Login SSH agent credentials forward
  #   through the Bastion to authenticate directly to siem-lab-wazuh.
  # - Option 2 (GCP CLI on Bastion): If executing gcloud CLI commands directly on the Bastion,
  #   run `gcloud auth login` on the Bastion or attach an IAM service account possessing
  #   roles/compute.osAdminLogin to the Bastion VM.
  gcloud compute ssh siem-lab-wazuh --zone=us-central1-a --internal-ip
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

# Push custom rules to SIEM manager (via OS Login / IAP tunnel)
gcloud compute scp wazuh/custom_rules/*.xml siem-lab-wazuh:/tmp/ --zone=us-central1-a --tunnel-through-iap

# On SIEM Manager: Install and verify syntax via OS Login
gcloud compute ssh siem-lab-wazuh --zone=us-central1-a --tunnel-through-iap --command="
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

### 7.1 Access & Import OpenSearch Dashboards
Access the Wazuh web user interface through an encrypted Google Cloud IAP port forwarding tunnel:
```bash
# 1. Open local encrypted IAP tunnel to Wazuh Dashboard (Port 443 -> localhost:8443)
gcloud compute start-iap-tunnel siem-lab-wazuh 443 --local-host-port=localhost:8443 --zone=us-central1-a

# 2. Access Wazuh Dashboard in your browser:
#    https://localhost:8443
```

Automatically import the customized SOC operational dashboards into the live Wazuh UI:
```bash
# Execute dashboard import script via the local IAP tunnel
bash wazuh/dashboards/import_dashboards.sh localhost:8443 <WAZUH_PASSWORD>
```

### 7.2 Standalone Interactive SOC Visualizer
Open `dashboards/index.html` in any modern browser to view interactive KPIs, MITRE ATT&CK charts, live alert feeds, and case records without needing active cloud instances.

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
