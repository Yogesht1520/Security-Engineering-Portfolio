#!/usr/bin/env bash
set -euo pipefail

CONF_FILE="${1:-/etc/wireguard/peer-configs/admin.conf}"
PEER_NAME=$(basename "$CONF_FILE" .conf)

echo "=========================================================="
echo " Testing WireGuard Peer Config: $PEER_NAME"
echo " Config Path: $CONF_FILE"
echo "=========================================================="

if [[ ! -f "$CONF_FILE" ]]; then
  echo "[ERROR] Config file not found: $CONF_FILE"
  exit 1
fi

# Clean up any leftover test namespaces/interfaces
ip netns del ns-peer-test 2>/dev/null || true
ip link del veth-ptest-br 2>/dev/null || true

# Setup virtual link between gateway host and simulated client peer
ip netns add ns-peer-test
ip link add veth-ptest type veth peer name veth-ptest-br
ip link set veth-ptest netns ns-peer-test

ip addr add 192.168.200.1/24 dev veth-ptest-br
ip link set veth-ptest-br up

ip netns exec ns-peer-test ip addr add 192.168.200.2/24 dev veth-ptest
ip netns exec ns-peer-test ip link set veth-ptest up
# Note: do NOT add a default route via veth-ptest!
# A remote VPN client does not have a direct physical Ethernet path to internal subnets.
# Only WireGuard AllowedIPs routes should handle internal destinations.

# Prepare peer configuration with the local test endpoint
TMP_CONF="/tmp/wg_test.conf"
sed -E "s|^Endpoint[[:space:]]*=.*|Endpoint = 192.168.200.1:51820|" "$CONF_FILE" > "$TMP_CONF"

# Bring up WireGuard inside client namespace using wg-quick
echo "Bringing up client interface inside ns-peer-test..."
ip netns exec ns-peer-test wg-quick up "$TMP_CONF"

echo ""
echo "--- Peer Routing Table (AllowedIPs Routes) ---"
ip netns exec ns-peer-test ip route

echo ""
echo "--- Testing Gateway Tunnel Ping (10.0.0.1) ---"
ip netns exec ns-peer-test ping -c 2 -W 2 10.0.0.1 || echo "Tunnel ping failed"

echo ""
echo "--- Gateway Handshake Status ---"
wg show wg0

echo ""
echo "--- Segment Reachability Tests ---"

echo -n "1. Dev Segment (10.10.1.2:8080): "
ip netns exec ns-peer-test curl -s --connect-timeout 2 http://10.10.1.2:8080 || echo "BLOCKED / TIMEOUT"

echo -n "2. Prod Segment (10.10.2.2:8080): "
ip netns exec ns-peer-test curl -s --connect-timeout 2 http://10.10.2.2:8080 || echo "BLOCKED / TIMEOUT"

echo -n "3. Corp-HR Segment (10.10.3.2:8080): "
ip netns exec ns-peer-test curl -s --connect-timeout 2 http://10.10.3.2:8080 || echo "BLOCKED / TIMEOUT"

# Teardown client interface and test namespace
echo ""
echo "Cleaning up test environment..."
ip netns exec ns-peer-test wg-quick down "$TMP_CONF" 2>/dev/null || true
rm -f "$TMP_CONF"
ip link del veth-ptest-br 2>/dev/null || true
ip netns del ns-peer-test 2>/dev/null || true

echo "=== Peer Test Completed ==="
