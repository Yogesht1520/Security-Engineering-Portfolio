#!/usr/bin/env bash
# =============================================================================
# import_dashboards.sh — Automated Wazuh / OpenSearch Dashboards Importer
#
# PURPOSE:
# Automatically imports custom SOC and detection engineering dashboards into
# the live Wazuh Dashboard via the OpenSearch Dashboards Saved Objects API.
#
# USAGE:
#   ./import_dashboards.sh [SIEM_HOST] [PASSWORD]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIEM_HOST="${1:-10.0.1.2}"
WAZUH_PASS="${2:-${WAZUH_PASSWORD:-}}"

if [ -z "$WAZUH_PASS" ]; then
  echo "[!] ERROR: Wazuh admin password required."
  echo "Usage: $0 [SIEM_HOST] <WAZUH_PASSWORD>"
  echo "Or set: export WAZUH_PASSWORD='...'"
  exit 1
fi

API_URL="https://${SIEM_HOST}/api/saved_objects/_import?overwrite=true"

echo "================================================================="
echo "       Wazuh OpenSearch Dashboards — Automated Import Tool       "
echo "================================================================="
echo "Target Manager: $SIEM_HOST"
echo "Import API:     $API_URL"
echo "-----------------------------------------------------------------"

for ndjson_file in "${SCRIPT_DIR}"/*.ndjson; do
  if [ -f "$ndjson_file" ]; then
    fname=$(basename "$ndjson_file")
    echo "[+] Importing saved objects from: $fname..."
    
    RESPONSE=$(curl -k -s -u "admin:${WAZUH_PASS}" \
      -X POST "$API_URL" \
      -H "osd-xsrf: true" \
      --form file=@"${ndjson_file}")
      
    SUCCESS=$(echo "$RESPONSE" | grep -o '"success":true' || true)
    if [ -n "$SUCCESS" ]; then
      echo "  [✓] Successfully imported $fname"
    else
      echo "  [!] Server response: $RESPONSE"
    fi
  fi
done

echo "-----------------------------------------------------------------"
echo "[+] Dashboards imported successfully. Access at https://${SIEM_HOST}"
echo "================================================================="
