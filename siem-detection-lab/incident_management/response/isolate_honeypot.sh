#!/usr/bin/env bash
# =============================================================================
# isolate_honeypot.sh — Emergency Honeypot Network Isolation Tool
#
# PURPOSE:
# Quickly isolates the honeypot instance during a suspected breach or active C2
# communication. Supports host-level iptables containment and GCP cloud firewall
# containment.
#
# SAFETY & RESTORATION GUARANTEES:
# - Confirmation prompt required unless --yes is passed
# - Cloud firewall isolation targets ONLY the tagged emergency quarantine rule
# - Host-level un-quarantine restores from persistent baseline rules (/etc/iptables/rules.v4)
#   ensuring host metadata protection (169.254.169.254 drop) remains strictly intact!
#
# USAGE:
#   ./isolate_honeypot.sh [--host|--cloud|--all] [--undo] [--yes]
# =============================================================================

set -uo pipefail

HONEYPOT_IP="${HONEYPOT_IP:-34.121.64.158}"
SIEM_IP="${SIEM_IP:-34.71.182.95}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/siem_lab_key}"
if [ ! -f "$SSH_KEY" ]; then
  for candidate in /mnt/c/Users/*/.ssh/siem_lab_key /c/Users/*/.ssh/siem_lab_key; do
    if [ -f "$candidate" ]; then
      mkdir -p "$HOME/.ssh"
      cp "$candidate" "$HOME/.ssh/siem_lab_key"
      chmod 600 "$HOME/.ssh/siem_lab_key"
      SSH_KEY="$HOME/.ssh/siem_lab_key"
      break
    fi
  done
fi
GCP_NETWORK_TAG="honeypot"
GCP_RULE_NAME="emergency-honeypot-quarantine"

MODE="all"
UNDO=false
AUTO_CONFIRM=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      MODE="host"
      shift
      ;;
    --cloud)
      MODE="cloud"
      shift
      ;;
    --all)
      MODE="all"
      shift
      ;;
    --undo|--restore)
      UNDO=true
      shift
      ;;
    --yes|-y)
      AUTO_CONFIRM=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--host|--cloud|--all] [--undo] [--yes]"
      exit 0
      ;;
    *)
      echo "[!] Unknown parameter: $1"
      exit 1
      ;;
  esac
done

echo "================================================================="
echo "       Emergency Incident Response — Honeypot Isolation         "
echo "================================================================="
echo "Target Honeypot: $HONEYPOT_IP"
echo "Target SIEM:     $SIEM_IP"
echo "Execution Mode:  $MODE"
echo "Action:          $([ "$UNDO" = true ] && echo "RESTORE / UN-QUARANTINE" || echo "ISOLATE / QUARANTINE")"
echo "Timestamp:       $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "-----------------------------------------------------------------"

if [ "$AUTO_CONFIRM" = false ]; then
  read -r -p "Are you sure you want to proceed with this operation? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "[!] Operation cancelled by user."
    exit 0
  fi
fi

# ── Function: Host-level iptables isolation ───────────────────────────────────
# ── Function: Host-level iptables isolation ───────────────────────────────────
isolate_host() {
  echo "[+] Applying host-level iptables quarantine on honeypot..."
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${HONEYPOT_IP}" bash -c "'
    set -eo pipefail
    sudo mkdir -p /var/backups
    sudo iptables-save > /var/backups/iptables_pre_quarantine.rules
    echo \"  [✓] Current firewall state backed up to /var/backups/iptables_pre_quarantine.rules\"

    sudo iptables -F
    sudo iptables -X
    
    # Allow loopback
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    
    # Keep metadata isolation intact during quarantine
    sudo iptables -A OUTPUT -d 169.254.169.254/32 -p tcp -j REJECT --reject-with tcp-reset
    
    # Allow established SSH session for SOC analyst
    sudo iptables -A INPUT -p tcp --dport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow Wazuh agent telemetry to internal SIEM Subnet Manager (10.0.20.2)
    sudo iptables -A OUTPUT -p tcp -d 10.0.20.2 --dport 1514 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp -d 10.0.20.2 --dport 1515 -j ACCEPT
    sudo iptables -A INPUT -p tcp -s 10.0.20.2 -j ACCEPT
    
    # DROP ALL other ingress and egress
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT DROP
    
    # Post-operation assertion: verify DROP policies are active
    INPUT_POL=\$(sudo iptables -L INPUT | head -n 1 | awk \"{print \\\$4}\" | tr -d \")\")
    OUTPUT_POL=\$(sudo iptables -L OUTPUT | head -n 1 | awk \"{print \\\$4}\" | tr -d \")\")
    if [ \"\$INPUT_POL\" != \"DROP\" ] || [ \"\$OUTPUT_POL\" != \"DROP\" ]; then
      echo \"[!] ERROR: Post-isolation check failed. Policies: INPUT=\$INPUT_POL OUTPUT=\$OUTPUT_POL\" >&2
      exit 1
    fi
    echo \"  [✓] Post-isolation assertion passed: INPUT=DROP, OUTPUT=DROP.\"
    sudo iptables -L -v -n
  '"
}

restore_host() {
  echo "[+] Restoring baseline host-level iptables networking on honeypot..."
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "ubuntu@${HONEYPOT_IP}" bash -c "'
    set -eo pipefail
    
    # Reload approved baseline rules to preserve metadata and egress protection
    if [ -f /etc/iptables/rules.v4 ]; then
      sudo iptables-restore < /etc/iptables/rules.v4
      echo \"  [✓] Host iptables baseline restored from /etc/iptables/rules.v4.\"
    elif [ -f /var/backups/iptables_pre_quarantine.rules ]; then
      sudo iptables-restore < /var/backups/iptables_pre_quarantine.rules
      echo \"  [✓] Host iptables restored from pre-quarantine backup.\"
    else
      # Reconstruct defense-in-depth baseline if backup files are absent
      sudo iptables -F
      sudo iptables -X
      
      # Allow loopback
      sudo iptables -A INPUT -i lo -j ACCEPT
      sudo iptables -A OUTPUT -o lo -j ACCEPT
      
      # Critical metadata server block
      sudo iptables -A OUTPUT -d 169.254.169.254/32 -p tcp -j REJECT --reject-with tcp-reset
      
      # Established connections
      sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      
      # Honeypot intentional SSH exposure
      sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
      
      # SIEM Telemetry Egress (10.0.20.2)
      sudo iptables -A OUTPUT -p tcp -d 10.0.20.2 --dport 1514 -j ACCEPT
      sudo iptables -A OUTPUT -p tcp -d 10.0.20.2 --dport 1515 -j ACCEPT
      
      # Explicit DNS Resolvers
      sudo iptables -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j ACCEPT
      sudo iptables -A OUTPUT -p udp -d 8.8.4.4 --dport 53 -j ACCEPT
      sudo iptables -A OUTPUT -p udp -d 1.1.1.1 --dport 53 -j ACCEPT
      sudo iptables -A OUTPUT -p tcp -d 8.8.8.8 --dport 53 -j ACCEPT
      sudo iptables -A OUTPUT -p tcp -d 8.8.4.4 --dport 53 -j ACCEPT
      sudo iptables -A OUTPUT -p tcp -d 1.1.1.1 --dport 53 -j ACCEPT
      
      # Ubuntu Package Repositories
      for cidr in 91.189.91.0/24 91.189.92.0/24 185.125.190.0/24 185.125.191.0/24; do
        sudo iptables -A OUTPUT -p tcp -d \"\$cidr\" --dport 80 -j ACCEPT
        sudo iptables -A OUTPUT -p tcp -d \"\$cidr\" --dport 443 -j ACCEPT
      done
      
      # Set default policies (default-deny outbound)
      sudo iptables -P INPUT ACCEPT
      sudo iptables -P FORWARD DROP
      sudo iptables -P OUTPUT DROP
      
      sudo mkdir -p /etc/iptables
      sudo iptables-save > /etc/iptables/rules.v4
      echo \"  [✓] Host iptables baseline reconstructed with strict egress controls and saved.\"
    fi

    # ── Post-Restoration Idempotency & Rule Verification ─────────────────────
    echo \"  [*] Performing post-restoration assertion on active iptables chains...\"
    
    # 1. Assert Metadata Block Rule exists
    if ! sudo iptables -C OUTPUT -d 169.254.169.254/32 -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null; then
      echo \"  [!] FATAL: Post-restoration check failed: Metadata block (169.254.169.254) missing!\" >&2
      exit 1
    fi
    
    # 2. Assert SIEM Manager Telemetry Egress rules exist
    if ! sudo iptables -C OUTPUT -p tcp -d 10.0.20.2 --dport 1514 -j ACCEPT 2>/dev/null; then
      echo \"  [!] FATAL: Post-restoration check failed: SIEM port 1514 egress missing!\" >&2
      exit 1
    fi
    if ! sudo iptables -C OUTPUT -p tcp -d 10.0.20.2 --dport 1515 -j ACCEPT 2>/dev/null; then
      echo \"  [!] FATAL: Post-restoration check failed: SIEM port 1515 egress missing!\" >&2
      exit 1
    fi
    
    # 3. Assert Port 22 Ingress Honeypot Target exists
    if ! sudo iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
      echo \"  [!] FATAL: Post-restoration check failed: SSH port 22 ingress missing!\" >&2
      exit 1
    fi
    
    echo \"  [✓] Post-restoration verification PASSED: Idempotent rule state confirmed active.\"
  '"
}

# ── Function: GCP Cloud Firewall isolation ────────────────────────────────────
isolate_cloud() {
  echo "[+] Enforcing GCP cloud-level firewall quarantine..."
  if ! command -v gcloud >/dev/null 2>&1; then
    echo "  [!] FATAL: gcloud CLI not detected locally. Cannot execute cloud firewall containment." >&2
    exit 1
  fi

  echo "  - Creating emergency high-priority GCP DENY firewall rule ($GCP_RULE_NAME)..."
  if ! gcloud compute firewall-rules create "$GCP_RULE_NAME" \
    --direction=INGRESS \
    --priority=10 \
    --action=DENY \
    --rules=all \
    --target-tags="$GCP_NETWORK_TAG" \
    --description="EMERGENCY INCIDENT RESPONSE: Quarantine honeypot ingress" \
    --quiet 2>/dev/null; then

    # Check idempotency: verify if the rule already exists and is active
    if gcloud compute firewall-rules describe "$GCP_RULE_NAME" --quiet >/dev/null 2>&1; then
      echo "  [✓] Emergency quarantine rule already exists and is currently enforced."
    else
      echo "  [!] FATAL: Failed to create GCP quarantine rule '$GCP_RULE_NAME'! Propagating error." >&2
      exit 1
    fi
  else
    echo "  [✓] GCP cloud firewall quarantine rule created successfully."
  fi
}

restore_cloud() {
  echo "[+] Restoring GCP cloud firewall..."
  if ! command -v gcloud >/dev/null 2>&1; then
    echo "  [!] FATAL: gcloud CLI not detected locally. Cannot verify cloud firewall state." >&2
    exit 1
  fi

  echo "  - Deleting emergency isolation firewall rule ($GCP_RULE_NAME)..."
  if ! gcloud compute firewall-rules delete "$GCP_RULE_NAME" --quiet 2>/dev/null; then
    if ! gcloud compute firewall-rules describe "$GCP_RULE_NAME" --quiet >/dev/null 2>&1; then
      echo "  [✓] Emergency quarantine rule was already absent."
    else
      echo "  [!] FATAL: Failed to delete GCP quarantine rule '$GCP_RULE_NAME'! Propagating error." >&2
      exit 1
    fi
  else
    echo "  [✓] Emergency quarantine firewall rule deleted successfully."
  fi
}

# ── Main Dispatch ─────────────────────────────────────────────────────────────
if [ "$UNDO" = true ]; then
  if [ "$MODE" = "host" ] || [ "$MODE" = "all" ]; then
    restore_host
  fi
  if [ "$MODE" = "cloud" ] || [ "$MODE" = "all" ]; then
    restore_cloud
  fi
  echo "[+] Honeypot isolation removed. Normal networking restored."
else
  if [ "$MODE" = "cloud" ] || [ "$MODE" = "all" ]; then
    isolate_cloud
  fi
  if [ "$MODE" = "host" ] || [ "$MODE" = "all" ]; then
    isolate_host
  fi
  echo "-----------------------------------------------------------------"
  echo "[!] QUARANTINE ACTIVE: Honeypot is isolated from public traffic."
  echo "    Wazuh agent can still send telemetry to SIEM Manager (10.0.20.2)."
  echo "================================================================="
fi
