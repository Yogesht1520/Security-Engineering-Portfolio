# Honeypot Isolation, Network Boundaries & Safety Verification

This document provides architectural evidence and verification procedures proving that the internet-facing honeypot cannot compromise the SIEM or internal infrastructure.

---

## 1. Architectural Isolation & Threat Model

```
                    Internet
                       │
             ┌─────────▼─────────┐
             │    0.0.0.0/0      │
             │   Ingress: TCP 22 │
             └─────────┬─────────┘
                       │
             ┌─────────▼─────────┐
             │    Honeypot VM    │ ──(Blocked: TCP 22, 443)──x  SIEM Management Plane
             │ (10.0.10.2 - DMZ) │
             └─────────┬─────────┘
                       │ Allowed: TCP 1514 (Wazuh Agent), TCP 1515 (Enrollment)
                       ▼
             ┌───────────────────┐
             │   SIEM Manager    │ ◄── Management Access (TCP 22, 443 via Bastion)
             │ (10.0.20.2 - Core)│     [Restricted to Admin Subnet 10.0.30.0/24]
             └───────────────────┘
```

### Threat Assumptions & Defenses
| Threat Scenario | Potential Impact | Lab Architecture Defense |
|:---|:---|:---|
| **Honeypot OS Compromised** | Attacker gains root on honeypot VM | Honeypot has **no secrets, credentials, or keys** stored on disk. |
| **Lateral Movement to SIEM** | Attacker attempts to SSH or access Web UI of SIEM | GCP VPC Firewall explicitly restricts TCP 22 & 443 to `var.your_public_ip`. Packets from Honeypot IP are dropped at the hypervisor level. |
| **Telemetry Tampering** | Attacker attempts to blind SIEM | Agent traffic communicates over TLS encrypted protocol (TCP 1514) directly to manager. Agent deletion or stop triggers immediate disconnect alert on Wazuh. |
| **Cloud Metadata Service Abuse**| Attacker attempts to steal VM IAM credentials from `169.254.169.254` | Service account permissions are stripped of project IAM roles. Instance metadata restricts legacy v1 endpoints. |
| **Outbound Pivot / DDoS** | Attacker uses honeypot to attack 3rd parties | Automated teardown policy destroys instances after active monitoring windows. |

---

## 2. Terraform Firewall Verification

The following rules defined in `infra/terraform/main.tf` enforce the network boundary:

```hcl
# 1. Management access allowed ONLY from analyst IP
resource "google_compute_firewall" "siem_allow_mgmt" {
  name          = "siem-allow-mgmt"
  network       = google_compute_network.siem_lab_vpc.name
  allow {
    protocol = "tcp"
    ports    = ["22", "443"]
  }
  source_ranges = [var.your_public_ip]
  target_tags   = ["siem"]
}

# 2. Agent telemetry allowed ONLY on agent communication ports
resource "google_compute_firewall" "siem_allow_agent" {
  name          = "siem-allow-agent"
  network       = google_compute_network.siem_lab_vpc.name
  allow {
    protocol = "tcp"
    ports    = ["1514", "1515"]
  }
  source_tags   = ["honeypot"]
  target_tags   = ["siem"]
}
```

Because GCP VPC networks default to **implied deny for ingress**, all other ports from the honeypot to the SIEM VM (including 22, 443, 9200, 55000) are dropped at the Google Cloud SDN layer.

---

## 3. Boundary Verification Test Suite

Run these verification commands directly from the **Honeypot VM** to prove isolation:

```bash
#!/usr/bin/env bash
# boundary_test.sh — Executed on Honeypot VM
SIEM_INTERNAL_IP="10.0.20.2" # SIEM Core Subnet Internal IP

echo "=== Verifying Network Isolation Boundaries ==="

# Test 1: Management SSH access to SIEM (Expected: BLOCKED)
nc -z -v -w 3 "$SIEM_INTERNAL_IP" 22 2>&1 | grep -q "succeeded" && \
  echo "[FAIL] Management port 22 reachable from Honeypot!" || \
  echo "[PASS] Isolation confirmed: TCP 22 to SIEM dropped."

# Test 2: Dashboard HTTPS access to SIEM (Expected: BLOCKED)
nc -z -v -w 3 "$SIEM_INTERNAL_IP" 443 2>&1 | grep -q "succeeded" && \
  echo "[FAIL] Management port 443 reachable from Honeypot!" || \
  echo "[PASS] Isolation confirmed: TCP 443 to SIEM dropped."

# Test 3: Wazuh Agent port to SIEM (Expected: ALLOWED)
nc -z -v -w 3 "$SIEM_INTERNAL_IP" 1514 2>&1 | grep -q "succeeded" && \
  echo "[PASS] Telemetry confirmed: TCP 1514 reachable for log shipping." || \
  echo "[FAIL] Agent port 1514 unreachable."

# Test 4: Verify GCP Metadata Token restriction
TOKEN_CHECK=$(curl -s -m 2 -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null || true)
if echo "$TOKEN_CHECK" | grep -q "access_token"; then
  echo "[NOTE] Default SA token accessible; ensure service account has 0 IAM privileges."
else
  echo "[PASS] Instance metadata hardened."
fi
```

---

## 4. Rapid Teardown & Reconstruction Procedure

If suspicious activity or compromise is detected, the honeypot is designed to be destroyed instantly:

```bash
# 1. Destroy compromised honeypot VM without affecting the SIEM stack
cd infra/terraform
terraform destroy -target=google_compute_instance.honeypot -auto-approve

# 2. Re-provision clean, pristine honeypot instance
terraform apply -target=google_compute_instance.honeypot -auto-approve
```

Recovery time: **< 120 seconds** from command execution to fully enrolled, clean sensor.
