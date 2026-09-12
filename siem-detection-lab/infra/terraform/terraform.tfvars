# ============================================================
# SIEM Detection Lab — terraform.tfvars 
# Fill in your real values below. 
# (This file is ignored by git so your credentials stay safe)
# ============================================================

# ── GCP Configuration ────────────────────────────────────────────────────────
project_id       = "siem-detection-lab"
region           = "us-central1"
zone             = "us-central1-a"
credentials_file = "C:/Users/yoges/Downloads/siem-detection-lab-3783874c813a.json"

# ── Access Control ────────────────────────────────────────────────────────────
# Your public IP — find it with: curl https://ifconfig.me
# This locks the SIEM dashboard (443) and SSH (22) to your IP only
# Format: "x.x.x.x/32"
your_public_ip = "58.84.62.206/32"

# ── SSH Key ───────────────────────────────────────────────────────────────────
# Path to the SSH public key to inject into both VMs
# Generate with: ssh-keygen -t rsa -b 4096 -f ~/.ssh/siem_lab_key
# In Windows, this is usually: "C:/Users/YourUsername/.ssh/siem_lab_key.pub"
ssh_public_key_path = "C:/Users/yoges/.ssh/siem_lab_key.pub"

# ── VM Sizing ─────────────────────────────────────────────────────────────────
honeypot_machine_type = "e2-micro"
siem_machine_type     = "e2-standard-2"
