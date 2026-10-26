#!/usr/bin/env python3
"""
reputation.py — Threat Intelligence Reputation Lookup Utility

Queries AbuseIPDB API for IP threat score, reports, and confidence.
Falls back to community reverse-DNS / threat feed heuristics if no API key is set.
"""

import os
import sys
import json
import socket
import urllib.request
import urllib.error

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

def check_reputation(ip_address: str, api_key: str = None) -> dict:
    if not api_key:
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")

    # Perform reverse DNS check regardless
    rdns = "None"
    try:
        rdns = socket.gethostbyaddr(ip_address)[0]
    except Exception:
        pass

    if not api_key:
        # Fallback heuristic mode when no external API key is provided
        return {
            "ip": ip_address,
            "status": "unauthenticated_fallback",
            "reverse_dns": rdns,
            "abuseipdb_score": None,
            "total_reports": None,
            "is_whitelisted": False,
            "note": "Set ABUSEIPDB_API_KEY environment variable for live AbuseIPDB scoring"
        }

    try:
        url = f"{ABUSEIPDB_API_URL}?ipAddress={ip_address}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(
            url,
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "SIEM-Lab-Enrichment/1.0"
            }
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            details = data.get("data", {})
            return {
                "ip": ip_address,
                "status": "success",
                "reverse_dns": rdns,
                "abuseipdb_score": details.get("abuseConfidenceScore"),
                "total_reports": details.get("totalReports"),
                "is_whitelisted": details.get("isWhitelisted", False),
                "last_reported_at": details.get("lastReportedAt"),
                "usage_type": details.get("usageType"),
                "country_code": details.get("countryCode")
            }
    except urllib.error.HTTPError as e:
        return {
            "ip": ip_address,
            "status": "error",
            "reverse_dns": rdns,
            "http_code": e.code,
            "message": str(e)
        }
    except Exception as e:
        return {
            "ip": ip_address,
            "status": "error",
            "reverse_dns": rdns,
            "message": str(e)
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 reputation.py <ip_address>")
        sys.exit(1)
    
    target_ip = sys.argv[1].strip()
    result = check_reputation(target_ip)
    print(json.dumps(result, indent=2))
