#!/usr/bin/env bash
# =============================================================================
# isolate_honeypot.sh — Emergency Honeypot Network Isolation Tool
#
# PURPOSE:
# Quickly isolates the honeypot instance during a suspected breach or active C2
# communication. Supports host-level iptables containment and GCP cloud firewall
# containment.
#
# USAGE:
#   ./isolate_honeypot.sh [--host|--cloud|--all] [--undo]
#
# EXAMPLES:
#   ./isolate_honeypot.sh --all          # Apply both host and GCP isolation
#   ./isolate_honeypot.sh --host         # Apply host-level iptables quarantine
#   ./isolate_honeypot.sh --undo         # Remove isolation rules and restore access
# =============================================================================

set -uo pipefail

HONEYPOT_IP="${HONEYPOT_IP:-34.121.64.158}"
SIEM_IP="${SIEM_IP:-34.71.182.95}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/siem_lab_key}"
GCP_ZONE="${GCP_ZONE:-us-central1-a}"
GCP_NETWORK_TAG="honeypot"
GCP_RULE_NAME="emergency-honeypot-quarantine"

MODE="all"
UNDO=false

# Parse command line flags
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
    -h|--help)
      echo "Usage: $0 [--host|--cloud|--all] [--undo]"
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
echo "Undo / Restore:  $UNDO"
echo "Timestamp:       $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "-----------------------------------------------------------------"

# ── Function: Host-level iptables isolation ───────────────────────────────────
isolate_host() {
  echo "[+] Applying host-level iptables quarantine on honeypot..."
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" bash -c "'
    sudo iptables -F
    sudo iptables -X
    
    # Allow loopback
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established SSH session for SOC analyst
    sudo iptables -A INPUT -p tcp --dport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow Wazuh agent telemetry to internal SIEM (10.0.1.2)
    sudo iptables -A OUTPUT -p tcp -d 10.0.1.2 --dport 1514 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp -d 10.0.1.2 --dport 1515 -j ACCEPT
    sudo iptables -A INPUT -p tcp -s 10.0.1.2 -j ACCEPT
    
    # DROP ALL other ingress and egress
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT DROP
    
    echo \"[+] Host iptables quarantine rules applied successfully.\"
    sudo iptables -L -v -n
  '"
}

restore_host() {
  echo "[+] Restoring normal host-level iptables networking on honeypot..."
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${HONEYPOT_IP}" bash -c "'
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -F
    sudo iptables -X
    echo \"[+] Host iptables reset to ACCEPT default.\"
  '"
}

# ── Function: GCP Cloud Firewall isolation ────────────────────────────────────
isolate_cloud() {
  echo "[+] Checking GCP CLI for cloud-level isolation..."
  if command -v gcloud >/dev/null 2>&1; then
    echo "  - Creating emergency high-priority GCP DENY firewall rule..."
    gcloud compute firewall-rules create "$GCP_RULE_NAME" \
      --direction=INGRESS \
      --priority=10 \
      --action=DENY \
      --rules=all \
      --target-tags="$GCP_NETWORK_TAG" \
      --description="EMERGENCY INCIDENT RESPONSE: Quarantine honeypot ingress" \
      --quiet || echo "  [!] Rule creation failed or rule already exists"
  else
    echo "  [!] gcloud CLI not detected locally. Skipping cloud firewall rule creation."
  fi
}

restore_cloud() {
  echo "[+] Restoring GCP cloud firewall..."
  if command -v gcloud >/dev/null 2>&1; then
    echo "  - Deleting emergency isolation firewall rule..."
    gcloud compute firewall-rules delete "$GCP_RULE_NAME" --quiet || echo "  [!] Rule deletion failed or rule does not exist"
  else
    echo "  [!] gcloud CLI not detected locally."
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
  echo "    Wazuh agent can still send telemetry to SIEM (10.0.1.2)."
  echo "================================================================="
fi
