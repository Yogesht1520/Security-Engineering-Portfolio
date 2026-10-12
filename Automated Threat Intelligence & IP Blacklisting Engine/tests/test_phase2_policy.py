"""
tests/test_phase2_policy.py — Unit tests for threshold evaluation and TTL policies
"""
from datetime import datetime, timedelta, timezone

from engine.policy import apply_policy
from models import RawIndicator


def _indicator(ip: str = "1.2.3.4", conf: float = 85.0) -> RawIndicator:
    return RawIndicator(
        ip=ip,
        source="abuseipdb",
        source_confidence=conf,
        category="brute-force",
        last_reported=datetime.now(timezone.utc),
    )


class TestPolicy:
    def test_above_threshold_action_is_block(self):
        cfg = {"confidence_threshold": 75, "ttl_days": 7}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=80.0, cfg=cfg)
        assert decision.action == "block"
        assert decision.scored_ip.ip == "1.2.3.4"

    def test_below_threshold_action_is_log_only(self):
        cfg = {"confidence_threshold": 75, "ttl_days": 7}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=70.0, cfg=cfg)
        assert decision.action == "log_only"

    def test_at_exact_threshold_is_block(self):
        cfg = {"confidence_threshold": 75, "ttl_days": 7}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=75.0, cfg=cfg)
        assert decision.action == "block"

    def test_new_ip_first_seen_set_to_now(self):
        now = datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc)
        cfg = {"confidence_threshold": 75, "ttl_days": 7}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=80.0, cfg=cfg, existing_record=None, now=now)
        assert decision.scored_ip.first_seen == now

    def test_new_ip_expires_at_is_now_plus_ttl(self):
        now = datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc)
        cfg = {"confidence_threshold": 75, "ttl_days": 10}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=80.0, cfg=cfg, existing_record=None, now=now)
        expected_expiry = now + timedelta(days=10)
        assert decision.scored_ip.expires_at == expected_expiry

    def test_existing_non_expired_ip_ttl_renewed(self):
        t0 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
        existing_expires = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        now = datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc)

        existing_record = {
            "ip": "1.2.3.4",
            "first_seen": t0.isoformat(),
            "expires_at": existing_expires.isoformat(),
            "combined_score": 75.0,
            "sources": ["abuseipdb"],
        }
        cfg = {"confidence_threshold": 70, "ttl_days": 7}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=85.0, cfg=cfg, existing_record=existing_record, now=now)

        # Original first_seen preserved, expiry pushed to now + 7 days
        assert decision.scored_ip.first_seen == t0
        assert decision.scored_ip.expires_at == now + timedelta(days=7)

    def test_post_expiry_ip_treated_as_new(self):
        t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        old_expiry = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        now = datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc)

        existing_record = {
            "ip": "1.2.3.4",
            "first_seen": t0.isoformat(),
            "expires_at": old_expiry.isoformat(),
            "combined_score": 75.0,
            "sources": ["abuseipdb"],
        }
        cfg = {"confidence_threshold": 70, "ttl_days": 7}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=85.0, cfg=cfg, existing_record=existing_record, now=now)

        # Expired IP gets a fresh first_seen = now
        assert decision.scored_ip.first_seen == now
        assert decision.scored_ip.expires_at == now + timedelta(days=7)

    def test_reason_string_not_empty(self):
        cfg = {"confidence_threshold": 75, "ttl_days": 7}
        decision = apply_policy("1.2.3.4", [_indicator()], combined_score=80.0, cfg=cfg)
        assert decision.reason
        assert isinstance(decision.reason, str)
        assert len(decision.reason) > 5
