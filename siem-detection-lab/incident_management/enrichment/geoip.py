#!/usr/bin/env python3
"""
geoip.py — Autonomous GeoIP Enrichment Utility

Looks up public IP address details via ip-api.com:
- Country
- City / Region
- ISP / Autonomous System Number (ASN)
"""

import sys
import json
import urllib.request
import urllib.error

def lookup_ip(ip_address: str) -> dict:
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,regionName,isp,as,query"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SIEM-Lab-Enrichment/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "ip": ip_address,
                    "status": "success",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown")
                }
            else:
                return {
                    "ip": ip_address,
                    "status": "fail",
                    "message": data.get("message", "Lookup failed")
                }
    except Exception as e:
        return {
            "ip": ip_address,
            "status": "error",
            "message": str(e)
        }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 geoip.py <ip_address>")
        sys.exit(1)
    
    target_ip = sys.argv[1].strip()
    result = lookup_ip(target_ip)
    print(json.dumps(result, indent=2))
