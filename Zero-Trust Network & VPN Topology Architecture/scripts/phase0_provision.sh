#!/usr/bin/env bash
# =============================================================================
# Phase 0 — Provision Infrastructure
# =============================================================================
# PURPOSE
#   Set up the gateway VM and simulate three isolated network segments
#   (Dev 10.10.1.0/24, Prod 10.10.2.0/24, Corp-HR 10.10.3.0/24) using Linux
#   network namespaces on a single free-tier VM. No extra cloud spend required.
#
# ACCEPTANCE CRITERIA (from spec)
#   All three segment "hosts" reachable from the gateway on their private IPs.
#
# ARCHITECTURE (namespace-based simulation)
#
#   [ Gateway / default netns ]
#        |        |        |
#   veth-dev  veth-prod  veth-hr     ← veth pairs bridge gateway → segment ns
#        |        |        |
#   [ ns-dev ] [ns-prod] [ns-hr]    ← each ns = isolated segment
#   10.10.1.1  10.10.2.1  10.10.3.1  ← gateway side of each pair
#   10.10.1.2  10.10.2.2  10.10.3.2  ← "host" side of each pair
#
# USAGE
#   sudo bash phase0_provision.sh [setup|teardown|status]
#
# REQUIRES: Linux kernel ≥ 5.6 (WireGuard built-in), iproute2, iptables/nftables
# =============================================================================

set -euo pipefail

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
DEV_GW="10.10.1.1"    ; DEV_HOST="10.10.1.2"   ; DEV_PREFIX="10.10.1.0/24"
PROD_GW="10.10.2.1"   ; PROD_HOST="10.10.2.2"  ; PROD_PREFIX="10.10.2.0/24"
HR_GW="10.10.3.1"     ; HR_HOST="10.10.3.2"    ; HR_PREFIX="10.10.3.0/24"

NS_DEV="ns-dev"
NS_PROD="ns-prod"
NS_HR="ns-hr"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
require_root() {
  [[ $EUID -eq 0 ]] || err "Run as root (sudo)"
}

install_dependencies() {
  log "Checking / installing dependencies…"
  apt-get update -qq
  # wireguard-tools provides wg(8) and wg-quick(8)
  apt-get install -y -qq \
    wireguard-tools \
    nftables \
    iproute2 \
    iputils-ping \
    curl \
    netcat-openbsd \
    tcpdump \
    jq
  log "Dependencies OK"
}

# Create a veth pair and move one end into a network namespace that acts as
# an isolated segment host.
#
# Args: <ns-name> <gw-ip> <host-ip> <prefix-len> <veth-gw-name> <veth-ns-name>
setup_segment() {
  local ns="$1" gw_ip="$2" host_ip="$3" prefix="$4"
  local veth_gw="veth-${ns}" veth_ns="veth-${ns}-in"
  local prefix_len="${prefix##*/}"

  log "Setting up segment: $ns ($gw_ip <-> $host_ip)"

  # Create namespace if not exists
  ip netns list | grep -q "^${ns}" || ip netns add "$ns"

  # Create veth pair
  if ! ip link show "$veth_gw" &>/dev/null; then
    ip link add "$veth_gw" type veth peer name "$veth_ns"
    ip link set "$veth_ns" netns "$ns"
  fi

  # Configure gateway-side interface
  ip addr flush dev "$veth_gw" 2>/dev/null || true
  ip addr add "${gw_ip}/${prefix_len}" dev "$veth_gw"
  ip link set "$veth_gw" up

  # Configure namespace-side interface + loopback
  ip netns exec "$ns" ip addr flush dev "$veth_ns" 2>/dev/null || true
  ip netns exec "$ns" ip addr add "${host_ip}/${prefix_len}" dev "$veth_ns"
  ip netns exec "$ns" ip link set "$veth_ns" up
  ip netns exec "$ns" ip link set lo up
  # Default route inside namespace: everything goes through the gateway
  ip netns exec "$ns" ip route replace default via "$gw_ip"

  log "  ✓ $ns ready — host $host_ip, gateway $gw_ip"
}

teardown_segment() {
  local ns="$1"
  local veth_gw="veth-${ns}"

  log "Tearing down segment: $ns"
  ip link del "$veth_gw" 2>/dev/null || true
  ip netns del "$ns"   2>/dev/null || true
}

# Enable IP forwarding and configure basic connectivity rules so the gateway
# can forward packets between WireGuard peers and the segment namespaces.
# The ZERO-TRUST enforcement rules are added separately in Phase 3.
enable_forwarding() {
  log "Enabling IP forwarding…"
  sysctl -qw net.ipv4.ip_forward=1
  # Persist across reboots
  grep -q "net.ipv4.ip_forward" /etc/sysctl.d/99-zt-lab.conf 2>/dev/null \
    || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.d/99-zt-lab.conf

  log "IP forwarding enabled"
}

start_dummy_services() {
  log "Starting dummy services in each segment namespace…"
  local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  # Kill any existing listeners before starting new ones
  pkill -f "mock_server.py" 2>/dev/null || true
  pkill -f "8080" 2>/dev/null || true

  for ns in "$NS_DEV" "$NS_PROD" "$NS_HR"; do
    # Start python server in background detached from terminal
    nohup ip netns exec "$ns" python3 "${script_dir}/mock_server.py" "$ns" </dev/null &>/var/log/zt-${ns}-svc.log &
  done

  log "  ✓ Dummy HTTP services running on port 8080 in each namespace"
  log "  ✓ Test: curl http://10.10.1.2:8080  (Dev)"
  log "  ✓ Test: curl http://10.10.2.2:8080  (Prod)"
  log "  ✓ Test: curl http://10.10.3.2:8080  (Corp-HR)"
}

# --------------------------------------------------------------------------- #
# Phase 0 — Main Actions
# --------------------------------------------------------------------------- #
do_setup() {
  require_root
  log "=== Phase 0: Provisioning infrastructure ==="

  install_dependencies
  enable_forwarding

  setup_segment "$NS_DEV"  "$DEV_GW"  "$DEV_HOST"  "$DEV_PREFIX"
  setup_segment "$NS_PROD" "$PROD_GW" "$PROD_HOST" "$PROD_PREFIX"
  setup_segment "$NS_HR"   "$HR_GW"   "$HR_HOST"   "$HR_PREFIX"

  start_dummy_services

  log ""
  log "=== Phase 0 Acceptance Test ==="
  log "Pinging all segment hosts from gateway…"
  local all_pass=true

  for host in "$DEV_HOST" "$PROD_HOST" "$HR_HOST"; do
    if ping -c2 -W2 "$host" &>/dev/null; then
      log "  ✓ PASS: gateway -> $host reachable"
    else
      log "  ✗ FAIL: gateway -> $host NOT reachable"
      all_pass=false
    fi
  done

  if $all_pass; then
    log ""
    log "✅ Phase 0 COMPLETE — all segment hosts reachable from gateway"
    log "   Proceed to: sudo bash phase1_wireguard.sh setup"
  else
    err "Phase 0 FAILED — check the output above"
  fi
}

do_teardown() {
  require_root
  log "=== Tearing down Phase 0 infrastructure ==="
  teardown_segment "$NS_DEV"
  teardown_segment "$NS_PROD"
  teardown_segment "$NS_HR"
  pkill -f "mock_server.py" 2>/dev/null || true
  pkill -f "nc -lp 8080" 2>/dev/null || true
  log "Teardown complete"
}

do_status() {
  log "=== Segment Status ==="
  for ns in "$NS_DEV" "$NS_PROD" "$NS_HR"; do
    echo -n "  $ns: "
    ip netns list | grep -q "^${ns}" && echo "EXISTS" || echo "not found"
  done
  log ""
  log "=== Reachability ==="
  for host in "$DEV_HOST" "$PROD_HOST" "$HR_HOST"; do
    echo -n "  gateway -> $host: "
    ping -c1 -W1 "$host" &>/dev/null && echo "reachable" || echo "UNREACHABLE"
  done
}

# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
ACTION="${1:-setup}"
case "$ACTION" in
  setup)    do_setup    ;;
  teardown) do_teardown ;;
  status)   do_status   ;;
  *)        echo "Usage: $0 [setup|teardown|status]"; exit 1 ;;
esac
