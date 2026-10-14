"""engine — deduplication, scoring, policy, expiry, validation, and fail-safe modules."""
from engine.dedup import deduplicate
from engine.expiry import ExpiryResult, sweep_expired
from engine.failsafe import (
    FeedStatus,
    OperationalState,
    PipelineHealthReport,
    evaluate_pipeline_health,
    should_freeze_ip_expiry,
)
from engine.policy import PolicyDecision, apply_policy
from engine.scoring import ScoreDetail, compute_score, compute_score_details
from engine.validator import (
    is_protected_network,
    parse_ip_or_network,
    sanitize_indicators,
    validate_and_normalize,
)

__all__ = [
    "deduplicate",
    "compute_score",
    "compute_score_details",
    "ScoreDetail",
    "apply_policy",
    "PolicyDecision",
    "sweep_expired",
    "ExpiryResult",
    "validate_and_normalize",
    "is_protected_network",
    "parse_ip_or_network",
    "sanitize_indicators",
    "OperationalState",
    "FeedStatus",
    "PipelineHealthReport",
    "evaluate_pipeline_health",
    "should_freeze_ip_expiry",
]
