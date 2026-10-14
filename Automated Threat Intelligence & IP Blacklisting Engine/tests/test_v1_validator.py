"""
tests/test_v1_validator.py — Tests for IP validation, dual-stack, and bogon safety
"""
from datetime import datetime, timezone

from engine.validator import (
    is_protected_network,
    parse_ip_or_network,
    sanitize_indicators,
    validate_and_normalize,
)
from models import RawIndicator


class TestIPValidation:
    def test_valid_ipv4_and_ipv6(self):
        v4 = parse_ip_or_network("198.51.100.25")
        assert v4 is not None and v4.version == 4

        v6 = parse_ip_or_network("2001:db8::1")
        assert v6 is not None and v6.version == 6

    def test_valid_cidr_network(self):
        net = parse_ip_or_network("198.51.100.0/24")
        assert net is not None
        assert str(net) == "198.51.100.0/24"

    def test_invalid_syntax_rejected(self):
        assert parse_ip_or_network("not-an-ip") is None
        assert parse_ip_or_network("999.999.999.999") is None
        assert parse_ip_or_network("") is None

    def test_loopback_protected(self):
        obj = parse_ip_or_network("127.0.0.1")
        is_prot, reason = is_protected_network(obj)
        assert is_prot is True
        assert "loopback" in reason

        v6_loop = parse_ip_or_network("::1")
        is_prot6, _ = is_protected_network(v6_loop)
        assert is_prot6 is True

    def test_rfc1918_private_protected(self):
        for priv in ["10.0.0.1", "172.16.5.10", "192.168.1.100", "10.200.0.0/16"]:
            obj = parse_ip_or_network(priv)
            is_prot, reason = is_protected_network(obj)
            assert is_prot is True, f"Failed for {priv}: {reason}"

    def test_link_local_and_multicast_protected(self):
        ll = parse_ip_or_network("169.254.10.20")
        assert is_protected_network(ll)[0] is True

        mc = parse_ip_or_network("224.0.0.5")
        assert is_protected_network(mc)[0] is True

    def test_custom_allowlist_protection(self):
        custom_allow = ["203.0.113.50", "198.51.100.0/28"]
        target_ip = parse_ip_or_network("203.0.113.50")
        is_prot, reason = is_protected_network(target_ip, custom_allowlist=custom_allow)
        assert is_prot is True
        assert "matched user allowlist" in reason

        subnet_ip = parse_ip_or_network("198.51.100.5")
        is_prot_sub, _ = is_protected_network(subnet_ip, custom_allowlist=custom_allow)
        assert is_prot_sub is True

    def test_sanitize_indicators_filters_bogons(self):
        now = datetime.now(timezone.utc)
        indicators = [
            RawIndicator("127.0.0.1", "abuseipdb", 90.0, "bad", now),
            RawIndicator("10.0.0.1", "otx", 80.0, "bad", now),
            RawIndicator("invalid-ip", "spamhaus", 70.0, "bad", now),
            RawIndicator("198.51.100.55", "abuseipdb", 85.0, "scanner", now),
            RawIndicator("2001:db8:85a3::8a2e:370:7334", "otx", 95.0, "c2", now),
        ]
        valid, rejected = sanitize_indicators(indicators)
        assert len(valid) == 2
        assert len(rejected) == 3
        valid_ips = {ind.ip for ind in valid}
        assert "198.51.100.55" in valid_ips
        assert "2001:db8:85a3::8a2e:370:7334" in valid_ips
