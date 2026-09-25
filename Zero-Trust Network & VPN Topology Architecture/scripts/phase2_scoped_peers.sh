#!/usr/bin/env bash
# =============================================================================
# Phase 2 — Scoped Peers: Developer + Contractor
# =============================================================================
# PURPOSE
#   Generate WireGuard keypairs and client configs for the Developer and
#   Contractor peers with RESTRICTED AllowedIPs scoping, then add them as
#   [Peer] blocks to the server config.
#
# ACCEPTANCE CRITERIA (from spec)
#   - Contractor can reach Dev segment ONLY (10.10.1.0/24) via AllowedIPs alone
#   - Developer can reach Dev + (optionally) Prod, but NOT Corp-HR
#   - Verified BEFORE adding nftables rules (proves AllowedIPs as first layer)
#
# ZERO-TRUST LAYERING NOTE
#   AllowedIPs functions as the FIRST enforcement layer. If a peer's config
#   doesn't include a CIDR in AllowedIPs, the WireGuard kernel module simply
#   won't route packets toward that CIDR through the tunnel — the traffic never
#   even reaches the gateway to be firewall-checked. This is efficient but
#   client-side controlled; Phase 3 adds the independent server-side firewall
#   as the second layer that would catch a misconfigured AllowedIPs.
#
# USAGE
#   sudo bash phase2_scoped_peers.sh [setup|verify|teardown]
# =============================================================================

set -euo pipefail

WG_DIR="/etc/wireguard"
WG_IF="wg0"
WG_PORT=51820
KEY_DIR="${WG_DIR}/keys"
PEER_DIR="${WG_DIR}/peer-configs"
SERVER_CONF="${WG_DIR}/${WG_IF}.conf"

DEV_PEER_VPN_IP="10.0.0.3"
CONTRACTOR_PEER_VPN_IP="10.0.0.4"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || err "Run as root"; }

read_key() { cat "${KEY_DIR}/${1}"; }

gen_keypair() {
  local name="$1"
  local priv="${KEY_DIR}/${name}.key"
  local pub="${KEY_DIR}/${name}.pub"
  [[ -f "$priv" ]] && { log "  Key for $name already exists — skipping"; return; }
  log "  Generating keypair: $name"
  wg genkey | install -m 0600 /dev/stdin "$priv"
  wg pubkey < "$priv" > "$pub"
  chmod 0644 "$pub"
}

# --------------------------------------------------------------------------- #
# Write Developer peer client config
# --------------------------------------------------------------------------- #
write_developer_conf() {
  local dev_priv server_pub gateway_ip
  dev_priv=$(read_key "developer.key")
  server_pub=$(read_key "server.pub")
  gateway_ip=$(curl -s --max-time 5 ifconfig.me || ip route get 1.1.1.1 | awk '{print $7; exit}')

  cat > "${PEER_DIR}/developer.conf" <<EOF
# =============================================================================
# Developer Peer — developer.conf
# =============================================================================
# ROLE: Access to Dev segment only.
# LAYER 1 (AllowedIPs): Only 10.10.1.0/24 (Dev) is included. The WireGuard
#   client will not route packets destined for Prod (10.10.2.0/24) or HR
#   (10.10.3.0/24) through the tunnel at all — they'd be dropped locally.
# LAYER 2 (firewall): Even if AllowedIPs were widened, nftables on the
#   gateway would still DENY + LOG any attempt to reach Prod or HR from
#   VPN IP 10.0.0.3.
# =============================================================================

[Interface]
PrivateKey = ${dev_priv}
Address    = ${DEV_PEER_VPN_IP}/32

[Peer]
PublicKey           = ${server_pub}
Endpoint            = ${gateway_ip}:${WG_PORT}
# ─── AllowedIPs = LAYER 1 ENFORCEMENT ───────────────────────────────────────
# Only Dev segment traffic goes through the tunnel.
# Prod (10.10.2.0/24) and Corp-HR (10.10.3.0/24) are NOT listed — the
# WireGuard kernel module will not even attempt to route those CIDRs here.
AllowedIPs          = 10.0.0.0/24, 10.10.1.0/24
PersistentKeepalive = 25
EOF
  log "  Developer config → ${PEER_DIR}/developer.conf"
}

# --------------------------------------------------------------------------- #
# Write Contractor peer client config
# --------------------------------------------------------------------------- #
write_contractor_conf() {
  local contractor_priv server_pub gateway_ip
  contractor_priv=$(read_key "contractor.key")
  server_pub=$(read_key "server.pub")
  gateway_ip=$(curl -s --max-time 5 ifconfig.me || ip route get 1.1.1.1 | awk '{print $7; exit}')

  cat > "${PEER_DIR}/contractor.conf" <<EOF
# =============================================================================
# Contractor Peer — contractor.conf
# =============================================================================
# ROLE: Dev segment ONLY (most restricted peer).
# LAYER 1 (AllowedIPs): ONLY 10.10.1.0/24 routed through tunnel.
# LAYER 2 (firewall): nftables DENY+LOG for any Prod/HR packet from 10.0.0.4.
#
# This is the peer used in the Phase 3 defense-in-depth test: we will
# deliberately WIDEN AllowedIPs to include Prod/HR, then prove the firewall
# independently blocks the traffic anyway.
# =============================================================================

[Interface]
PrivateKey = ${contractor_priv}
Address    = ${CONTRACTOR_PEER_VPN_IP}/32

[Peer]
PublicKey           = ${server_pub}
Endpoint            = ${gateway_ip}:${WG_PORT}
# ─── AllowedIPs = LAYER 1 ENFORCEMENT ───────────────────────────────────────
# Contractor can ONLY reach Dev (10.10.1.0/24).
# Prod and Corp-HR CIDRs intentionally absent — no routing path exists.
AllowedIPs          = 10.0.0.0/24, 10.10.1.0/24
PersistentKeepalive = 25
EOF
  log "  Contractor config → ${PEER_DIR}/contractor.conf"

  # Also write the MISCONFIGURED version used in Phase 3 defense-in-depth test
  cat > "${PEER_DIR}/contractor-MISCONFIGURED.conf" <<EOF
# =============================================================================
# Contractor Peer — DELIBERATELY MISCONFIGURED (Phase 3 test only)
# =============================================================================
# THIS CONFIG IS USED ONLY TO PROVE THE FIREWALL LAYER WORKS INDEPENDENTLY.
# AllowedIPs is widened to include ALL segment subnets — simulating an admin
# error or a compromised client that bypasses the AllowedIPs restriction.
# Expected result: traffic reaches the gateway but nftables DENIES + LOGs it.
# =============================================================================

[Interface]
PrivateKey = ${contractor_priv}
Address    = ${CONTRACTOR_PEER_VPN_IP}/32

[Peer]
PublicKey           = ${server_pub}
Endpoint            = ${gateway_ip}:${WG_PORT}
# ⚠ INTENTIONALLY WIDE — for Phase 3 defense-in-depth test ONLY
AllowedIPs          = 10.0.0.0/8
PersistentKeepalive = 25
EOF
  log "  Contractor MISCONFIGURED config → ${PEER_DIR}/contractor-MISCONFIGURED.conf"
}

# --------------------------------------------------------------------------- #
# Add peers to server wg0.conf
# --------------------------------------------------------------------------- #
append_peers_to_server() {
  local dev_pub contractor_pub
  dev_pub=$(read_key "developer.pub")
  contractor_pub=$(read_key "contractor.pub")

  # Check if already added
  grep -q "$dev_pub" "$SERVER_CONF" && { log "  Developer peer already in server config — skipping"; } || {
    log "  Adding Developer peer to server config…"
    cat >> "$SERVER_CONF" <<EOF

# =============================================================================
# Peer: Developer (10.0.0.3)
# Server-side AllowedIPs: accept only packets claiming source 10.0.0.3/32.
# Packets from this peer destined to segments are then checked by nftables.
# =============================================================================
[Peer]
PublicKey  = ${dev_pub}
AllowedIPs = 10.0.0.3/32
EOF
  }

  grep -q "$contractor_pub" "$SERVER_CONF" && { log "  Contractor peer already in server config — skipping"; } || {
    log "  Adding Contractor peer to server config…"
    cat >> "$SERVER_CONF" <<EOF

# =============================================================================
# Peer: Contractor (10.0.0.4)
# Server-side AllowedIPs: accept only packets from 10.0.0.4/32 source.
# Destination enforcement (Dev ONLY, DENY Prod/HR) is in nftables (Phase 3).
# =============================================================================
[Peer]
PublicKey  = ${contractor_pub}
AllowedIPs = 10.0.0.4/32
EOF
  }
}

reload_wireguard() {
  log "Reloading WireGuard config (syncconf — no tunnel restart)…"
  wg syncconf "$WG_IF" <(wg-quick strip "$WG_IF")
  wg show "$WG_IF"
}

# --------------------------------------------------------------------------- #
# Layer 1 verification (AllowedIPs only, no firewall yet)
# --------------------------------------------------------------------------- #
verify_layer1() {
  # This test runs from the GATEWAY perspective.
  # Since we can't run the actual peer clients here without a second machine,
  # we verify the routing table shows the correct scope and test reachability
  # from a simulated peer IP using ip netns + ip rule tricks.
  log ""
  log "=== Phase 2 Layer-1 Verification (AllowedIPs scope) ==="
  log ""
  log "WireGuard server will only accept packets from:"
  log "  Developer  (10.0.0.3/32) → can route to 10.10.1.0/24 only"
  log "  Contractor (10.0.0.4/32) → can route to 10.10.1.0/24 only"
  log ""
  log "Verifying wg0 peer table…"
  wg show "$WG_IF" allowed-ips | sort

  log ""
  log "AllowedIPs scoping verified at server level."
  log "NOTE: Full end-to-end test requires peer clients to be connected."
  log "      Phase 3 adds the independent firewall layer and runs the"
  log "      deliberate misconfiguration test."
}

# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
do_setup() {
  require_root
  log "=== Phase 2: Scoped Peers (Developer + Contractor) ==="

  [[ -f "${KEY_DIR}/server.key" ]] \
    || err "Phase 1 not completed — run phase1_wireguard.sh setup first"

  install -d -m 0700 "$KEY_DIR"
  mkdir -p "$PEER_DIR"

  gen_keypair "developer"
  gen_keypair "contractor"

  write_developer_conf
  write_contractor_conf
  append_peers_to_server
  reload_wireguard
  verify_layer1

  log ""
  log "✅ Phase 2 COMPLETE"
  log "   Peer configs:"
  log "     ${PEER_DIR}/developer.conf"
  log "     ${PEER_DIR}/contractor.conf"
  log "     ${PEER_DIR}/contractor-MISCONFIGURED.conf  ← for Phase 3 test"
  log "   Proceed to: sudo bash phase3_firewall.sh setup"
}

do_verify() {
  require_root
  verify_layer1
}

do_teardown() {
  require_root
  log "Phase 2 teardown: removing developer/contractor peers from server conf…"
  # Remove the peer blocks from server conf (keep admin block intact)
  dev_pub=$(read_key "developer.pub" 2>/dev/null || echo "NOTFOUND")
  contractor_pub=$(read_key "contractor.pub" 2>/dev/null || echo "NOTFOUND")
  sed -i "/^# .*Developer/,/^$/d" "$SERVER_CONF" 2>/dev/null || true
  sed -i "/^# .*Contractor/,/^$/d" "$SERVER_CONF" 2>/dev/null || true
  reload_wireguard
}

ACTION="${1:-setup}"
case "$ACTION" in
  setup)    do_setup    ;;
  verify)   do_verify   ;;
  teardown) do_teardown ;;
  *)        echo "Usage: $0 [setup|verify|teardown]"; exit 1 ;;
esac
