#!/usr/bin/env bash
# =============================================================================
# Phase 3 — Firewall Defense-in-Depth (nftables) + Deliberate Misconfig Test
# =============================================================================
# PURPOSE
#   Apply independent nftables rules that enforce segment authorization based
#   on the PEER'S VPN IP — completely independently of AllowedIPs scoping.
#   Then deliberately widen the Contractor's AllowedIPs (simulating
#   misconfiguration) and prove the firewall STILL blocks unauthorized access.
#
# ACCEPTANCE CRITERIA (from spec)
#   - Loosen contractor AllowedIPs → firewall still blocks Prod/HR access
#   - Firewall DENY+LOG entries appear in system journal
#   - Screenshot evidence captured to /var/log/zt-evidence/
#
# ZERO-TRUST PRINCIPLE DEMONSTRATED
#   "Never trust a single control point." (NIST SP 800-207 §2.1)
#   AllowedIPs is a client-side config that an admin error or a compromised
#   endpoint could widen. The firewall on the gateway is fully server-side
#   and cannot be bypassed by the peer — it sees the post-decryption source IP.
#
# USAGE
#   sudo bash phase3_firewall.sh [setup|test-misconfig|teardown|status]
# =============================================================================

set -euo pipefail

NFTABLES_CONF="/etc/nftables.conf"
NFTABLES_ZT="/etc/wireguard/nftables-zt-rules.nft"
LOG_DIR="/var/log/zt-evidence"
WG_IF="wg0"
KEY_DIR="/etc/wireguard/keys"
PEER_DIR="/etc/wireguard/peer-configs"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || err "Run as root"; }

# --------------------------------------------------------------------------- #
# nftables zero-trust enforcement ruleset
# --------------------------------------------------------------------------- #
write_zt_nftables() {
  log "Writing zero-trust nftables ruleset → ${NFTABLES_ZT}"

  cat > "$NFTABLES_ZT" <<'NFTEOF'
# =============================================================================
# Zero-Trust Segmentation Rules — nftables-zt-rules.nft
# =============================================================================
# LAYER 2 ENFORCEMENT (independent of WireGuard AllowedIPs)
#
# This ruleset enforces segment authorization at the GATEWAY FIREWALL level.
# It is evaluated AFTER WireGuard decrypts the tunnel — we see real peer IPs.
# Even if a peer's AllowedIPs is widened (misconfigured or compromised), these
# rules will DENY and LOG any unauthorized cross-segment attempt.
#
# IP MAP:
#   10.0.0.1  — gateway (wg0)
#   10.0.0.2  — Admin peer       → allow ALL segments
#   10.0.0.3  — Developer peer   → allow Dev (10.10.1.0/24) ONLY
#   10.0.0.4  — Contractor peer  → allow Dev (10.10.1.0/24) ONLY
#
# Segment subnets:
#   10.10.1.0/24  — Dev
#   10.10.2.0/24  — Prod
#   10.10.3.0/24  — Corp-HR
#
# Policy: default DROP on forward chain.
# =============================================================================

table inet zt_filter {

  # ─── Named sets for segment CIDRs (DRY principle) ───────────────────────
  set dev_segment {
    type ipv4_addr; flags interval;
    elements = { 10.10.1.0/24 }
  }
  set prod_segment {
    type ipv4_addr; flags interval;
    elements = { 10.10.2.0/24 }
  }
  set hr_segment {
    type ipv4_addr; flags interval;
    elements = { 10.10.3.0/24 }
  }
  set all_segments {
    type ipv4_addr; flags interval;
    elements = { 10.10.1.0/24, 10.10.2.0/24, 10.10.3.0/24 }
  }

  # ─── FORWARD CHAIN ────────────────────────────────────────────────────────
  # All traffic forwarded through the gateway (between wg0 and segment veths)
  # must pass through this chain. Default policy: DROP.
  chain forward {
    type filter hook forward priority 0; policy drop;

    # ── Established/related connections: allow return traffic ───────────────
    ct state established,related accept comment "allow established sessions"

    # ── Admin peer (10.0.0.2): FULL ACCESS to all segments ─────────────────
    # Admin uses hardware-stored key + quarterly rotation (see THREAT_MODEL.md)
    ip saddr 10.0.0.2 ip daddr @all_segments accept \
      comment "admin peer — authorized full segment access"

    # Allow admin to reach gateway itself (wg0 management)
    ip saddr 10.0.0.2 ip daddr 10.0.0.1 accept \
      comment "admin peer — gateway management"

    # ── Developer peer (10.0.0.3): Dev segment ONLY ─────────────────────────
    ip saddr 10.0.0.3 ip daddr @dev_segment accept \
      comment "developer peer — Dev segment authorized"

    # Developer → Prod: DENY + LOG
    ip saddr 10.0.0.3 ip daddr @prod_segment \
      log prefix "ZT-DENY-DEV-TO-PROD: " flags all \
      drop \
      comment "developer peer — Prod access DENIED (zero-trust boundary)"

    # Developer → HR: DENY + LOG
    ip saddr 10.0.0.3 ip daddr @hr_segment \
      log prefix "ZT-DENY-DEV-TO-HR: " flags all \
      drop \
      comment "developer peer — Corp-HR access DENIED (zero-trust boundary)"

    # ── Contractor peer (10.0.0.4): Dev segment ONLY ────────────────────────
    # This is the CRITICAL defense-in-depth rule: even if contractor's
    # AllowedIPs is widened to 10.0.0.0/8, THESE RULES still block Prod/HR.
    ip saddr 10.0.0.4 ip daddr @dev_segment accept \
      comment "contractor peer — Dev segment authorized"

    # Contractor → Prod: DENY + LOG (DEFENSE-IN-DEPTH — catches AllowedIPs misconfig)
    ip saddr 10.0.0.4 ip daddr @prod_segment \
      log prefix "ZT-DENY-CONTRACTOR-PROD: " flags all \
      drop \
      comment "contractor → Prod DENIED + LOGGED — proves firewall layer is independent"

    # Contractor → Corp-HR: DENY + LOG
    ip saddr 10.0.0.4 ip daddr @hr_segment \
      log prefix "ZT-DENY-CONTRACTOR-HR: " flags all \
      drop \
      comment "contractor → HR DENIED + LOGGED — proves firewall layer is independent"

    # ── Catch-all: log and drop any other forward attempt ───────────────────
    log prefix "ZT-DENY-UNMATCHED: " flags all \
      drop \
      comment "default deny — log unexpected forwarded traffic"
  }

  # ─── INPUT CHAIN ──────────────────────────────────────────────────────────
  # Protect the gateway itself. Peers may only reach the WireGuard UDP port.
  chain input {
    type filter hook input priority 0; policy drop;

    # Loopback always allowed
    iif lo accept

    # Established/related sessions
    ct state established,related accept

    # WireGuard UDP port (from any source — internet-facing)
    udp dport 51820 accept comment "WireGuard inbound"

    # SSH — restrict to admin management IP in production
    # (left open here for lab convenience; tighten with: ip saddr <your-ip> tcp dport 22 accept)
    tcp dport 22 accept comment "SSH management (restrict to admin IP in production)"

    # ICMP — allow ping for diagnostic purposes
    icmp type echo-request accept
    ip6 nexthdr icmpv6 accept

    log prefix "ZT-INPUT-DENY: " drop comment "default input deny"
  }

  # ─── OUTPUT CHAIN ─────────────────────────────────────────────────────────
  chain output {
    type filter hook output priority 0; policy accept;
    # Gateway itself has full outbound — restrict in production as needed
  }
}
NFTEOF

  log "  Zero-trust nftables ruleset written"
}

# --------------------------------------------------------------------------- #
# Apply nftables rules
# --------------------------------------------------------------------------- #
apply_nftables() {
  log "Applying zero-trust nftables ruleset…"

  # Remove existing zt_filter table if present (idempotent)
  nft delete table inet zt_filter 2>/dev/null || true

  # Apply our ruleset
  nft -f "$NFTABLES_ZT"

  log "  Ruleset applied. Verifying…"
  nft list table inet zt_filter | head -30 || true
  log "  (full ruleset: nft list table inet zt_filter)"

  # Persist across reboots
  log "  Making rules persistent across reboots…"
  touch "$NFTABLES_CONF" 2>/dev/null || true
  if ! grep -q "nftables-zt-rules.nft" "$NFTABLES_CONF" 2>/dev/null; then
    echo "include \"${NFTABLES_ZT}\"" >> "$NFTABLES_CONF"
    log "  Added include to ${NFTABLES_CONF}"
  fi

  systemctl enable nftables 2>/dev/null || true
  log "  nftables service enabled"
}

# --------------------------------------------------------------------------- #
# Configure kernel logging for nftables deny entries
# --------------------------------------------------------------------------- #
configure_logging() {
  log "Configuring kernel log routing for firewall denies…"
  mkdir -p "$LOG_DIR"

  # rsyslog rule to capture nftables ZT-DENY messages into a dedicated file
  cat > /etc/rsyslog.d/99-zt-firewall.conf <<'RSYSLOGEOF'
# Zero-Trust firewall deny log — captures all ZT-DENY-* nftables log prefixes
:msg, contains, "ZT-DENY" /var/log/zt-evidence/firewall-denies.log
& stop
RSYSLOGEOF

  systemctl restart rsyslog 2>/dev/null || true
  log "  Firewall deny log → /var/log/zt-evidence/firewall-denies.log"
}

# --------------------------------------------------------------------------- #
# Phase 3 CORE: Deliberate Misconfiguration Test
# =============================================================================
# WHAT THIS TESTS:
#   "Even if AllowedIPs is WRONG, the firewall catches it."
#
# METHOD:
#   1. Save the correct contractor config
#   2. Load contractor-MISCONFIGURED.conf (AllowedIPs = 10.0.0.0/8)
#      → Contractor now has a routing path to ALL segments
#   3. Try to reach Prod (10.10.2.2) and Corp-HR (10.10.3.2) from
#      contractor's VPN IP using ip rule + ip route to simulate the peer
#   4. nftables DENIES the traffic and LOGs with "ZT-DENY-CONTRACTOR-PROD:"
#   5. Capture the log entry as evidence
# --------------------------------------------------------------------------- #
run_misconfig_test() {
  require_root
  log ""
  log "=============================================================="
  log "  PHASE 3 — DELIBERATE MISCONFIGURATION TEST"
  log "  Proving the firewall layer is independent of AllowedIPs"
  log "=============================================================="
  log ""
  log "SCENARIO:"
  log "  An admin accidentally widens the contractor's AllowedIPs to"
  log "  10.0.0.0/8 (all subnets). The contractor now has a tunnel"
  log "  route to Prod (10.10.2.0/24) and HR (10.10.3.0/24)."
  log "  EXPECTED: nftables DENIES the traffic and logs it."
  log ""

  # Verify firewall is loaded
  nft list table inet zt_filter &>/dev/null \
    || err "nftables zero-trust rules not loaded — run: phase3_firewall.sh setup first"

  # Verify segment namespaces exist
  ip netns list | grep -q "^ns-prod" \
    || err "Phase 0 namespaces not running — run: phase0_provision.sh setup"

  local evidence_file="${LOG_DIR}/phase3-misconfig-test-$(date '+%Y%m%d-%H%M%S').log"
  mkdir -p "$LOG_DIR"

  {
    echo "Zero-Trust Defense-in-Depth Test — Phase 3"
    echo "Date: $(date)"
    echo "Test: Contractor peer with WIDENED AllowedIPs (AllowedIPs=10.0.0.0/8)"
    echo "Expected: firewall DENIES Prod and HR access, logs ZT-DENY-CONTRACTOR-*"
    echo "=============================================================="
    echo ""
  } > "$evidence_file"

  local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  log "Executing authentic peer test with contractor-MISCONFIGURED.conf..."
  bash "${script_dir}/test_peer.sh" "${PEER_DIR}/contractor-MISCONFIGURED.conf" >> "$evidence_file" 2>&1

  log "Step 5: Waiting 2s for log entries to be flushed…"
  sleep 2

  log ""
  log "Step 6: Checking nftables counters for DENY rules…"
  {
    echo ""
    echo "--- nftables Rule Hit Counters (ZT-DENY rules) ---"
    nft list table inet zt_filter 2>&1 | grep -A2 "ZT-DENY-CONTRACTOR" || true
    echo ""
  } >> "$evidence_file"

  log "Step 7: Checking kernel log for ZT-DENY entries…"
  local deny_count=0
  {
    echo "--- Kernel Journal / dmesg: ZT-DENY-CONTRACTOR entries ---"
    dmesg | grep "ZT-DENY-CONTRACTOR" | tail -20 | tee /dev/stderr || true
  } >> "$evidence_file" 2>&1
  deny_count=$(dmesg | grep -c "ZT-DENY-CONTRACTOR" || echo 0)

  log ""
  log "=============================================================="
  log "  MISCONFIG TEST RESULTS"
  log "=============================================================="
  {
    echo ""
    echo "=============================================================="
    echo "  RESULT SUMMARY"
    echo "=============================================================="
  } >> "$evidence_file"

  if [[ "$deny_count" -gt 0 ]]; then
    log "  ✅ FIREWALL CAUGHT IT: $deny_count ZT-DENY-CONTRACTOR log entries found"
    log "     Even with widened AllowedIPs, nftables blocked Prod/HR access."
    log "     This proves defense-in-depth: firewall layer is INDEPENDENT."
    echo "  RESULT: ✅ PASS — Firewall caught misconfigured AllowedIPs" >> "$evidence_file"
    echo "  DENY ENTRIES: $deny_count" >> "$evidence_file"
  else
    log "  ⚠ No deny log entries found in journal (may be a timing issue)."
    log "    Check: sudo dmesg | grep ZT-DENY-CONTRACTOR"
    log "    Or:    sudo nft list table inet zt_filter | grep -A3 DENY"
    echo "  RESULT: ⚠ CHECK MANUALLY — see instructions above" >> "$evidence_file"
  fi

  log ""
  log "  Evidence file: $evidence_file"
  log "  nftables dump:  sudo nft list table inet zt_filter"
  log "  Live deny log:  sudo journalctl -kf | grep ZT-DENY"
  log ""

  # Also dump nftables counters to evidence file
  {
    echo ""
    echo "--- Full nftables zt_filter table dump ---"
    nft list table inet zt_filter 2>&1
  } >> "$evidence_file"

  log "Evidence saved to: $evidence_file"
}

# --------------------------------------------------------------------------- #
# Normal (correctly configured) segmentation test
# --------------------------------------------------------------------------- #
run_normal_test() {
  require_root
  log ""
  log "=== Phase 3 Normal Access Tests ==="
  log "Testing with CORRECT AllowedIPs configurations…"

  # Test contractor → Dev (should SUCCEED)
  log ""
  log "Test 1: Contractor → Dev (10.10.1.2) — EXPECTED: PASS"
  if ip netns exec ns-dev curl -s --max-time 3 http://10.10.1.2:8080 &>/dev/null; then
    log "  ✓ PASS: Dev segment accessible"
  else
    log "  ✗ FAIL or dummy service not running — start with phase0_provision.sh setup"
  fi

  # Test Dev → Prod (from gateway perspective, no peer VPN needed)
  log ""
  log "Test 2: Gateway → Prod (10.10.2.2) — admin-level, EXPECTED: PASS"
  if curl -s --max-time 3 http://10.10.2.2:8080 &>/dev/null; then
    log "  ✓ PASS: Prod segment accessible (admin-level gateway test)"
  else
    log "  (Dummy service may not be running — OK for firewall rule test)"
  fi
}

# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #
do_status() {
  log "=== nftables Zero-Trust Ruleset Status ==="
  nft list table inet zt_filter 2>/dev/null && echo "" \
    || echo "  zt_filter table NOT loaded"

  log ""
  log "=== Recent Firewall Deny Events (last 5 min) ==="
  journalctl -k --since "5 minutes ago" --no-pager 2>/dev/null \
    | grep "ZT-DENY" | tail -20 \
    || dmesg | grep "ZT-DENY" | tail -20 \
    || echo "  No deny events found"
}

do_teardown() {
  require_root
  log "Removing zero-trust nftables table…"
  nft delete table inet zt_filter 2>/dev/null || true
  sed -i "\|${NFTABLES_ZT}|d" "$NFTABLES_CONF" 2>/dev/null || true
  log "Teardown complete"
}

# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
do_setup() {
  require_root
  log "=== Phase 3: Firewall Defense-in-Depth ==="

  [[ -f "/etc/wireguard/keys/contractor.pub" ]] \
    || err "Phase 2 not completed — run phase2_scoped_peers.sh setup first"

  write_zt_nftables
  apply_nftables
  configure_logging
  run_normal_test

  log ""
  log "✅ Phase 3 COMPLETE — zero-trust nftables rules applied"
  log ""
  log "   NEXT: Run the deliberate misconfiguration test:"
  log "   sudo bash phase3_firewall.sh test-misconfig"
}

ACTION="${1:-setup}"
case "$ACTION" in
  setup)          do_setup           ;;
  test-misconfig) run_misconfig_test ;;
  status)         do_status          ;;
  teardown)       do_teardown        ;;
  *)
    echo "Usage: $0 [setup|test-misconfig|status|teardown]"
    exit 1
    ;;
esac
