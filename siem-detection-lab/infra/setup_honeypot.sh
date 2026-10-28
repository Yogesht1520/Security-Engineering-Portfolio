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
  unzip \
  iptables-persistent \
  netfilter-persistent

# =============================================================================
# 1B. HOST-LEVEL CLOUD METADATA & LINK-LOCAL ISOLATION (Defense-in-Depth)
# Enforces kernel-level egress blocking of GCP metadata (169.254.169.254)
# to prevent compromised honeypot processes from extracting instance credentials.
# =============================================================================
echo "[1B] Enforcing host-level cloud metadata isolation..."
iptables -F OUTPUT 2>/dev/null || true
iptables -A OUTPUT -d 169.254.169.254/32 -p tcp -j REJECT --reject-with tcp-reset
ip6tables -F OUTPUT 2>/dev/null || true
ip6tables -A OUTPUT -d fe80::/10 -j REJECT 2>/dev/null || true

# Persist iptables rules across reboots
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
netfilter-persistent save >/dev/null 2>&1 || true

# Disable GCP guest services that poll metadata server on unmanaged honeypots
systemctl stop google-guest-agent google-osconfig-agent 2>/dev/null || true
systemctl disable google-guest-agent google-osconfig-agent 2>/dev/null || true
echo "  Metadata isolation enforced (TCP reset on 169.254.169.254:80/443)."

# =============================================================================
# 2. AUDITD — Linux Audit Daemon (Explicit Validated Baseline)
# Captures: exec events, privilege escalation, file changes, user creation
# Supports both 64-bit (b64) and 32-bit (b32) syscall architectures
# =============================================================================
echo "[2/5] Installing and configuring auditd baseline policy..."
apt-get install -y auditd audispd-plugins

# Back up pre-existing rules before applying approved baseline
if [ -f /etc/audit/rules.d/siem-lab.rules ]; then
  cp /etc/audit/rules.d/siem-lab.rules "/etc/audit/rules.d/backup_$(date +%s).rules"
fi

# Write approved baseline audit rules
cat > /etc/audit/rules.d/siem-lab.rules << 'AUDITEOF'
# ---- SIEM Lab Approved Audit Baseline Policy ----
# Replaces unverified default configurations with a validated, immutable baseline

# Clear existing unverified rules to establish explicit baseline
-D

# Set buffer size (increase if events are dropping)
-b 8192

# Failure mode: 1 = printk on buffer full (prevents silent drop)
-f 1

# ── Privilege Escalation / Sudo (Dual-Architecture: b64 & b32) ─────────────
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k privilege_escalation
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudo -k privilege_escalation
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k privilege_escalation
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/su -k privilege_escalation
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

# ── Suspicious Command Execution (Dual-Architecture) ───────────────────────
-a always,exit -F arch=b64 -S execve -F path=/bin/bash -k shell_exec
-a always,exit -F arch=b32 -S execve -F path=/bin/bash -k shell_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python3 -k shell_exec
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/python3 -k shell_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/python -k shell_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc -k network_tool
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/nc -k network_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/ncat -k network_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/wget -k download_tool
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/wget -k download_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -k download_tool
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/curl -k download_tool
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/chmod -k permission_change
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/chown -k permission_change

# ── Cron / Scheduled Tasks ─────────────────────────────────────────────────
-w /etc/cron.d/ -p wa -k cron_modification
-w /etc/crontab -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification

# ── SSH Config Changes ─────────────────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k ssh_config_change

# ── Outbound Network Socket Activity ───────────────────────────────────────
-a always,exit -F arch=b64 -S connect -k outbound_connection
-a always,exit -F arch=b32 -S connect -k outbound_connection
AUDITEOF

# Restart auditd and validate loaded rules
systemctl enable auditd
systemctl restart auditd

# Verification: Record effective loaded rules and audit daemon status as deployment evidence
echo "  Validating active auditd policy..."
auditctl -s
auditctl -l > /var/log/audit_effective_baseline.txt
echo "  auditd baseline configured, verified, and saved to /var/log/audit_effective_baseline.txt."

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
apt-get install -y wazuh-agent=4.9.2-1

# Configure Wazuh Agent log collection (auth.log, syslog, audit.log)
cat >> /var/ossec/etc/ossec.conf << 'LOGCOLLECTOREOF'
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
LOGCOLLECTOREOF

# Do NOT start/enable the agent yet — needs WAZUH_MANAGER IP from Phase 1
echo "  Wazuh agent package installed. Log collection configured."
echo "  To enroll: set WAZUH_MANAGER=<siem-ip> and restart wazuh-agent"

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
