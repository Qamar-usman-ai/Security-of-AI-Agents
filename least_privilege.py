"""
(3) Least-Privilege / Role-Based Access Control.

Agents get the MINIMUM access required for their job, checked at
request time — never standing broad permissions.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Role:
    name: str
    allowed_scopes: frozenset
    forbidden_scopes: frozenset = frozenset()

ROLE_POLICIES = {
    "finance-agent":   Role("finance-agent", frozenset({"invoice:read", "payment:draft"}), frozenset({"payment:execute"})),
    "hr-agent":        Role("hr-agent", frozenset({"employee:read:basic"}), frozenset({"salary:read", "employee:delete"})),
    "procurement-agent": Role("procurement-agent", frozenset({"vendor:read", "order:draft"}), frozenset({"payment:execute"})),
    "sales-agent":     Role("sales-agent", frozenset({"crm:read", "docs:read", "email:send"}), frozenset({"pricing:write"})),
}

class LeastPrivilegeAccessControl:
    """Enforce role scopes + per-request justification. Deny by default."""

    def check(self, agent_scopes: list[str], role: str, requested_scope: str,
              justification: str | None = None) -> bool:
        policy = ROLE_POLICIES.get(role)
        if policy is None:
            return False                                            # unknown role → deny
        if requested_scope in policy.forbidden_scopes:
            return False                                            # explicitly forbidden
        if requested_scope not in policy.allowed_scopes:
            return False                                            # not in least-privilege set
        if not justification and requested_scope.endswith(("write", "execute", "delete")):
            return False                                            # sensitive scopes need justification
        return requested_scope in set(agent_scopes)                 # agent must be provisioned for it
