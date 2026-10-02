"""
(1) Execution Guardrails — hard boundaries on what an agent may execute.

Principle (Question 1): an agent can DRAFT a large payment, but final
approval must require human intervention. Limits apply at ACTION level.
"""
from __future__ import annotations
import functools, time, yaml
from dataclasses import dataclass, field
from typing import Callable, Any


@dataclass
class RateLimiter:
    """Sliding-window rate limit per agent+action (stops runaway loops)."""
    window_seconds: int = 60
    max_calls: int = 10
    _hits: dict = field(default_factory=dict)

    def allow(self, key: str) -> bool:
        now = time.time()
        self._hits[key] = [t for t in self._hits.get(key, []) if now - t < self.window_seconds]
        if len(self._hits[key]) >= self.max_calls:
            return False
        self._hits[key].append(now)
        return True


class ActionGuardrails:
    """Declares per-action-type limits and approval thresholds from policy YAML."""

    def __init__(self, policy: dict):
        self.actions = policy.get("actions", {})
        self.rate = RateLimiter(**policy.get("rate_limit", {}))

    @classmethod
    def from_yaml(cls, path: str) -> "ActionGuardrails":
        with open(path) as f:
            return cls(yaml.safe_load(f))

    def requires_approval(self, action_type: str, value: float | None = None) -> bool:
        rule = self.actions.get(action_type, {})
        if rule.get("requires_human_approval", False):
            return True                                   # e.g. payments: ALWAYS human-approved
        threshold = rule.get("human_approval_threshold")
        return threshold is not None and value is not None and value > threshold

    def denylisted(self, action_type: str) -> bool:
        return self.actions.get(action_type, {}).get("deny", False)

    def protect(self, action_type: str, audit=None) -> Callable:
        """Decorator: enforce deny-list + rate limits + audit around any tool call."""
        def deco(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                if self.denylisted(action_type):
                    raise PermissionError(f"Action '{action_type}' is deny-listed by policy.")
                agent_id = kwargs.get("agent_id", "unknown-agent")
                if not self.rate.allow(f"{agent_id}:{action_type}"):
                    raise RuntimeError(f"Rate limit exceeded for '{action_type}'. Possible runaway agent.")
                if audit:
                    audit.log_action(agent_id=agent_id, user_id=kwargs.get("user_id"),
                                     action=action_type, detail={"args": str(args)[:500],
                                     "kwargs": {k: v for k, v in kwargs.items() if k != "agent_id"}})
                return fn(*args, **kwargs)
            return wrapper
        return deco
