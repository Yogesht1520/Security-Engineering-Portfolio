"""engine — deduplication, scoring, policy, and expiry modules."""
from engine.dedup import deduplicate
from engine.expiry import ExpiryResult, sweep_expired
from engine.policy import PolicyDecision, apply_policy
from engine.scoring import compute_score

__all__ = [
    "deduplicate",
    "compute_score",
    "apply_policy",
    "PolicyDecision",
    "sweep_expired",
    "ExpiryResult",
]
