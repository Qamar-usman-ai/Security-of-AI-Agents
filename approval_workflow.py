"""
(1) Human-in-the-Loop Approval — async approval gate for critical actions.

Mirrors CIBA-style flows: agent pauses, rich context goes to an
approver (mobile/email), agent resumes only on APPROVE with a
time-bound, scope-limited authorization.
"""
from __future__ import annotations
import time, uuid
from dataclasses import dataclass, field
from enum import Enum

class ApprovalChannel(Enum):
    MOBILE = "mobile"
    EMAIL = "email"

@dataclass
class ApprovalDecision:
    approved: bool
    approver: str
    reason: str = ""
    auth_token: str = field(default_factory=lambda: f"auth_{uuid.uuid4().hex[:16]}")
    expires_at: float = field(default_factory=lambda: time.time() + 300)  # 5-min bound
    scopes: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return time.time() < self.expires_at

class ApprovalWorkflow:
    def __init__(self, approvers: list[tuple[str, ApprovalChannel]],
                 rotation: bool = True, auto_expire_seconds: int = 300):
        self.approvers = approvers
        self.rotation = rotation
        self.auto_expire = auto_expire_seconds
        self._rr_index = 0
        self.pending: dict[str, dict] = {}

    def _pick_approver(self, group: str | None = None) -> tuple[str, ApprovalChannel]:
        if self.rotation:
            a = self.approvers[self._rr_index % len(self.approvers)]
            self._rr_index += 1
            return a
        return self.approvers[0]

    def request(self, approver_group: str, context: dict,
                scopes: list[str] | None = None) -> ApprovalDecision:
        """Simulated async request. In production: POST to IdP CIBA endpoint,
        push notify approver's mobile, await callback."""
        approver, channel = self._pick_approver()
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        self.pending[request_id] = {"context": context, "scopes": scopes or [], "approver": approver}
        # ---- DEMO auto-approve for testing; production waits for human callback ----
        return self.resolve(request_id, approved=True, approver=approver)

    def resolve(self, request_id: str, approved: bool, approver: str,
                reason: str = "") -> ApprovalDecision:
        p = self.pending.pop(request_id)
        return ApprovalDecision(approved=approved, approver=approver, reason=reason,
                                scopes=p["scopes"] if approved else [])
