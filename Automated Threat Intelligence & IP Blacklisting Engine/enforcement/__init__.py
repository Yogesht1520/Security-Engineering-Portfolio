"""enforcement — firewall and WAF adapter modules."""
from enforcement.base_adapter import BaseEnforcer, EnforcerError
from enforcement.local_firewall import LocalFirewallAdapter
from enforcement.aws_waf import AWSWAFAdapter
from enforcement.result import EnforcementResult

__all__ = [
    "BaseEnforcer",
    "EnforcerError",
    "LocalFirewallAdapter",
    "AWSWAFAdapter",
    "EnforcementResult",
]
