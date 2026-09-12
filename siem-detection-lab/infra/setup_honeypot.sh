#!/usr/bin/env bash
# =============================================================================
# setup_honeypot.sh — Honeypot VM Bootstrap
# Phase 0: Runs automatically on first boot via cloud-init (user_data)
# Phase 2: Re-run manually with WAZUH_MANAGER_IP set to enroll agent
#
# What this does:
#   1. System updates + essential packages
#   2. Install auditd + configure exec/file-watch audit rules
#   3. Harden SSH: disable password auth (key-only), keep port 22 open
#   4. Install Wazuh agent package (enrollment done in Phase 2)
#   5. Set up a minimal motd warning ("DO NOT STORE SENSITIVE DATA")
#
# What this does NOT do (intentionally):
#   - Does NOT close port 22 or add fail2ban (this is a honeypot — we want traffic)
#   - Does NOT configure the agent (needs SIEM IP from Phase 1)
# =============================================================================

set -euo pipefail
LOG="/var/log/siem-lab-bootstrap.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== Honeypot Bootstrap Start: $(date) ==="

# =============================================================================
# 1. SYSTEM UPDATES
# =============================================================================
echo "[1/5] Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y --no-install-recommends
apt-get install -y \
  curl \
  wget \
  gnupg \
  apt-transport-https \
  lsb-release \
  net-tools \
  jq \
  unzip

# =============================================================================
# 2. AUDITD — Linux Audit Daemon
# Captures: exec events, privilege escalation, file changes, user creation
# =============================================================================
echo "[2/5] Installing and configuring auditd..."
apt-get install -y auditd audispd-plugins

# Write audit rules for Wazuh agent to ship
cat > /etc/audit/rules.d/siem-lab.rules << 'AUDITEOF'
# ---- SIEM Lab Audit Rules ----
# These rules feed Wazuh's detection engine

# Delete all existing rules first
-D

# Set buffer size (increase if events are dropping)
-b 8192

# ── Privilege Escalation / Sudo ────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k privilege_escalation
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k privilege_escalation
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

# ── User/Group Management ──────────────────────────────────────────────────
-w /etc/passwd -p wa -k user_modification
-w /etc/group -p wa -k user_modification
-w /etc/shadow -p wa -k user_modification
-w /usr/sbin/useradd -p x -k user_creation
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_deletion
-w /usr/sbin/groupadd -p x -k group_modification

# ── Suspicious Command Execution ───────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F path=/bin/bash -k shell_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python3 -k shell_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python -k shell_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc -k network_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ncat -k network_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k download_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k download_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/chmod -k permission_change
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/chown -k permission_change

# ── Cron / Scheduled Tasks ─────────────────────────────────────────────────
-w /etc/cron.d/ -p wa -k cron_modification
-w /etc/crontab -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification

# ── SSH Config Changes ─────────────────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k ssh_config_change

# ── Network Connections (for detecting reverse shells) ─────────────────────
-a always,exit -F arch=b64 -S connect -k outbound_connection

# Make rules immutable until reboot (optional — comment out during testing)
# -e 2
AUDITEOF

# Restart auditd to apply rules
systemctl enable auditd
systemctl restart auditd
echo "  auditd configured and running."

# =============================================================================
# 3. SSH HARDENING
# Key-only auth (no passwords), but SSH stays on port 22 and exposed.
# This is intentional — we harden the auth method while keeping the honeypot
# visible to scanners. Attackers will try password auth and fail → alerts fire.
# =============================================================================
echo "[3/5] Hardening SSH (disable password auth, keep port 22 open)..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Apply hardening settings
cat >> /etc/ssh/sshd_config << 'SSHEOF'

# ---- SIEM Lab Hardening ----
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
MaxAuthTries 6
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
SSHEOF

systemctl reload sshd
echo "  SSH hardened: password auth disabled, key-only access."

# =============================================================================
# 4. WAZUH AGENT — Install (enrollment configured in Phase 2)
# =============================================================================
echo "[4/5] Installing Wazuh agent package..."

# Add Wazuh repository (GPG key + apt source)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list

apt-get update -y
apt-get install -y wazuh-agent

# Do NOT start/enable the agent yet — needs WAZUH_MANAGER IP from Phase 1
echo "  Wazuh agent package installed. Enrollment deferred to Phase 2."
echo "  To enroll (Phase 2): set WAZUH_MANAGER_IP and run:"
echo "    WAZUH_MANAGER=<siem-ip> systemctl restart wazuh-agent"

# =============================================================================
# 5. MOTD — Disposable Lab Warning
# =============================================================================
echo "[5/5] Setting MOTD warning..."
cat > /etc/motd << 'MOTDEOF'
╔══════════════════════════════════════════════════════════════════╗
║           ⚠️  HONEYPOT / LAB MACHINE — DO NOT TRUST  ⚠️          ║
║                                                                  ║
║  This is an intentionally exposed honeypot for SIEM lab use.    ║
║  DO NOT store any credentials, secrets, or sensitive data here. ║
║  Treat as fully disposable. Destroy when not monitoring.        ║
╚══════════════════════════════════════════════════════════════════╝
MOTDEOF

# =============================================================================
# DONE
# =============================================================================
echo ""
echo "=== Honeypot Bootstrap Complete: $(date) ==="
echo ""
echo "Next steps:"
echo "  Phase 1: Install Wazuh stack on SIEM VM"
echo "  Phase 2: Set WAZUH_MANAGER=<siem-ip> and restart wazuh-agent"
echo ""
echo "Logs: $LOG"
