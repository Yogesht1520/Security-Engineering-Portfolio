#!/usr/bin/env bash
# =============================================================================
# Phase 1 — WireGuard Server + Admin Peer
# =============================================================================
# PURPOSE
#   Install and configure the WireGuard VPN gateway on the host. Generate
#   keypairs for the server and the Admin peer. Bring up the WireGuard interface
#   (wg0) and verify the Admin peer can reach all three segment hosts.
#
# ACCEPTANCE CRITERIA (from spec)
#   `wg show` shows an active handshake; admin can ping all segment hosts.
#
# IP ADDRESS PLAN
#   WireGuard tunnel subnet: 10.0.0.0/24
#     10.0.0.1  — gateway (server)
#     10.0.0.2  — Admin peer
#     10.0.0.3  — Developer peer   (Phase 2)
#     10.0.0.4  — Contractor peer  (Phase 2)
#
#   Segment subnets (established in Phase 0):
#     10.10.1.0/24 — Dev
#     10.10.2.0/24 — Prod
#     10.10.3.0/24 — Corp-HR
#
# USAGE
#   sudo bash phase1_wireguard.sh [setup|teardown|status]
# =============================================================================

set -euo pipefail

WG_DIR="/etc/wireguard"
WG_IF="wg0"
WG_PORT=51820
SERVER_VPN_IP="10.0.0.1/24"
ADMIN_VPN_IP="10.0.0.2"

KEY_DIR="${WG_DIR}/keys"
LOG_FILE="/var/log/zt-wireguard-setup.log"

log()  { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || err "Run as root"; }

# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
gen_keypair() {
  # Args: <name>
  # Writes <name>.key (private) and <name>.pub (public) under KEY_DIR
  local name="$1"
  local priv="${KEY_DIR}/${name}.key"
  local pub="${KEY_DIR}/${name}.pub"

  [[ -f "$priv" ]] && { log "  Key for $name already exists — skipping generation"; return; }

  log "  Generating keypair for: $name"
  wg genkey | install -m 0600 /dev/stdin "$priv"
  wg pubkey < "$priv" > "$pub"
  chmod 0644 "$pub"
}

read_key() { cat "${KEY_DIR}/${1}"; }

# --------------------------------------------------------------------------- #
# Build server wg0.conf
# --------------------------------------------------------------------------- #
write_server_conf() {
  local server_priv admin_pub
  server_priv=$(read_key "server.key")
  admin_pub=$(read_key "admin.pub")

  log "Writing server config: ${WG_DIR}/${WG_IF}.conf"

  cat > "${WG_DIR}/${WG_IF}.conf" <<EOF
# =============================================================================
# WireGuard Gateway — wg0.conf
# =============================================================================
# ZERO-TRUST NOTE: This file alone does NOT enforce zero-trust. It establishes
# the cryptographic tunnel. Per-peer segment authorization is enforced by:
#   1. AllowedIPs scoping in each [Peer] block (what THIS server will route
#      *to* each peer — acting as an egress filter for inbound-from-peer traffic)
#   2. nftables rules in /etc/nftables.conf (independent second control point)
# =============================================================================

[Interface]
# Server's VPN tunnel IP
Address = ${SERVER_VPN_IP}

# WireGuard listens on UDP 51820. Open this in your cloud security group.
ListenPort = ${WG_PORT}

PrivateKey = ${server_priv}

# IP forwarding must be enabled (done by phase0_provision.sh).
# PostUp/PostDown manage the nftables integration — see firewall/nftables.conf.
PostUp   = nft -f /etc/wireguard/nftables-wg-hooks.nft
PostDown = nft delete table inet wg_nat 2>/dev/null; true

# =============================================================================
# Peer: Admin  (10.0.0.2)
# AllowedIPs = 10.0.0.2/32 means the server will route traffic that *arrives
# from* this peer's public key, and will only send *back* to 10.0.0.2/32.
# On the peer side (admin.conf), AllowedIPs = 0.0.0.0/0 gives full-tunnel
# routing — the admin routes ALL traffic through the VPN.
# =============================================================================
[Peer]
# identity = cryptographic public key, not a username or IP
PublicKey  = ${admin_pub}
# Server-side AllowedIPs: packets arriving from this peer claiming a source
# outside 10.0.0.2/32 will be dropped by WireGuard before even hitting nftables.
AllowedIPs = 10.0.0.2/32
EOF

  chmod 0600 "${WG_DIR}/${WG_IF}.conf"
  log "  Server config written"
}

# --------------------------------------------------------------------------- #
# Build Admin peer config
# --------------------------------------------------------------------------- #
write_admin_conf() {
  local admin_priv server_pub gateway_ip
  admin_priv=$(read_key "admin.key")
  server_pub=$(read_key "server.pub")
  # Auto-detect public IP (replace with your VM's actual IP in production)
  gateway_ip=$(curl -s --max-time 5 ifconfig.me || ip route get 1.1.1.1 | awk '{print $7; exit}')

  local out_dir="${WG_DIR}/peer-configs"
  mkdir -p "$out_dir"

  cat > "${out_dir}/admin.conf" <<EOF
# =============================================================================
# Admin Peer — admin.conf
# =============================================================================
# ROLE: Full access to all three segments (Dev, Prod, Corp-HR).
# AllowedIPs = 10.0.0.0/8 routes ALL segment traffic through the tunnel.
# The firewall (nftables) allows ip saddr 10.0.0.2 to reach any destination.
#
# SECURITY IMPLICATION: Admin key compromise = full lateral movement.
# Mitigations: store key in a hardware token / secrets manager; rotate quarterly.
# =============================================================================

[Interface]
PrivateKey = ${admin_priv}
# Admin's VPN tunnel IP
Address    = ${ADMIN_VPN_IP}/32
# Optional: route all Internet through tunnel too (comment out for split-tunnel)
# DNS      = 1.1.1.1

[Peer]
PublicKey           = ${server_pub}
# Gateway public endpoint — update with your VM's actual public IP/FQDN
Endpoint            = ${gateway_ip}:${WG_PORT}
# AllowedIPs: which destination CIDRs this peer will route through the tunnel.
# 10.0.0.0/8 covers the VPN subnet AND all three segment subnets.
AllowedIPs          = 10.0.0.0/8
PersistentKeepalive = 25
EOF

  log "  Admin peer config written to: ${out_dir}/admin.conf"
}

# --------------------------------------------------------------------------- #
# Minimal nftables hook for WireGuard NAT (PostUp)
# Full zero-trust enforcement rules are applied in Phase 3.
# --------------------------------------------------------------------------- #
write_wg_nat_nft() {
  cat > "${WG_DIR}/nftables-wg-hooks.nft" <<'EOF'
# Minimal WireGuard NAT table (applied by wg0 PostUp)
# Masquerade outbound traffic from the VPN subnet so segment hosts
# see replies arrive from the gateway's veth interface IP, not the peer's VPN IP.
# (In production you'd use static routes; masquerade keeps the lab self-contained.)

table inet wg_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    # Masquerade traffic leaving toward each segment subnet
    ip saddr 10.0.0.0/24 ip daddr 10.10.1.0/24 masquerade
    ip saddr 10.0.0.0/24 ip daddr 10.10.2.0/24 masquerade
    ip saddr 10.0.0.0/24 ip daddr 10.10.3.0/24 masquerade
  }
}
EOF
  log "  WireGuard NAT nftables hook written"
}

# --------------------------------------------------------------------------- #
# Phase 1 — Actions
# --------------------------------------------------------------------------- #
do_setup() {
  require_root
  log "=== Phase 1: WireGuard Server + Admin Peer ==="

  # Verify Phase 0 completed
  ip netns list | grep -q "^ns-dev" \
    || err "Phase 0 not completed — run phase0_provision.sh setup first"

  # Prepare key directory with strict permissions
  install -d -m 0700 "$KEY_DIR"

  # Generate keys
  log "Generating cryptographic keypairs…"
  gen_keypair "server"
  gen_keypair "admin"

  # Build configs
  write_server_conf
  write_admin_conf
  write_wg_nat_nft

  # Bring up WireGuard interface
  log "Starting WireGuard interface (${WG_IF})…"
  wg-quick down "$WG_IF" 2>/dev/null || true
  wg-quick up   "$WG_IF"

  log ""
  log "=== wg show output ==="
  wg show "$WG_IF"

  log ""
  log "=== Phase 1 Acceptance Test ==="
  log "NOTE: Full admin-peer handshake requires the admin client to be running."
  log "      Testing gateway-side routing to segments (prerequisite for handshake)…"

  local all_pass=true
  for host in 10.10.1.2 10.10.2.2 10.10.3.2; do
    if ping -c2 -W2 "$host" &>/dev/null; then
      log "  ✓ PASS: gateway -> $host reachable (routing layer OK)"
    else
      log "  ✗ FAIL: gateway -> $host NOT reachable"
      all_pass=false
    fi
  done

  if $all_pass; then
    log ""
    log "✅ Phase 1 COMPLETE"
    log "   Server config:    ${WG_DIR}/${WG_IF}.conf"
    log "   Admin peer config: ${WG_DIR}/peer-configs/admin.conf"
    log "   → Copy admin.conf to the admin client machine and run: wg-quick up admin"
    log "   → Then run: sudo wg show   (expect to see latest-handshake update)"
    log "   Proceed to: sudo bash phase2_scoped_peers.sh setup"
  else
    err "Phase 1 FAILED"
  fi
}

do_teardown() {
  require_root
  log "Bringing down WireGuard interface…"
  wg-quick down "$WG_IF" 2>/dev/null || true
  log "WireGuard stopped"
}

do_status() {
  log "=== WireGuard Status ==="
  wg show "$WG_IF" 2>/dev/null || echo "Interface $WG_IF is not up"
}

ACTION="${1:-setup}"
case "$ACTION" in
  setup)    do_setup    ;;
  teardown) do_teardown ;;
  status)   do_status   ;;
  *)        echo "Usage: $0 [setup|teardown|status]"; exit 1 ;;
esac
