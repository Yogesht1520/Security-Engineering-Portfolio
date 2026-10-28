#!/usr/bin/env python3
"""
geoip.py — Autonomous GeoIP Enrichment Utility

Looks up public IP address details via encrypted HTTPS:
- RFC1918 / Loopback / Bogon pre-validation (prevents private IP leakage)
- Encrypted HTTPS lookup via ip-api.com
- Enriches: Country, City / Region, ISP, ASN
"""

import sys
import json
import ipaddress
import urllib.request
import urllib.error

def lookup_ip(ip_address: str) -> dict:
    clean_ip = ip_address.strip()
    
    # 1. IP address syntactic and scope validation
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError as e:
        return {
            "ip": clean_ip,
            "status": "error",
            "message": f"Invalid IP address format: {e}"
        }

    # 2. Strict Bogon & Internal RFC1918 filter — Never query third parties for private IPs
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
        return {
            "ip": clean_ip,
            "status": "success",
            "country": "Internal / RFC1918",
            "city": "Private Network",
            "region": "Local Infrastructure",
            "isp": "Private Enterprise Routing",
            "asn": "AS0 (Internal)"
        }

    # 3. Encrypted HTTPS external enrichment for public addresses
    url = f"https://ip-api.com/json/{clean_ip}?fields=status,message,country,city,regionName,isp,as,query"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SIEM-Lab-Enrichment/2.0 (Security Engineering Lab)"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "ip": clean_ip,
                    "status": "success",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown")
                }
            else:
                return {
                    "ip": clean_ip,
                    "status": "fail",
                    "message": data.get("message", "Lookup failed")
                }
    except Exception as e:
        return {
            "ip": clean_ip,
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
