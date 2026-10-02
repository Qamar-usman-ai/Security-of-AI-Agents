"""
(10) Automation-Bias Defense — rotate reviewers, force fresh eyes.

Humans over-trust AI ("rubber-stamping"). Mitigations:
round-robin rotation, mandatory secondary review above risk
thresholds, cooldown after N consecutive approvals.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field

@dataclass
class ReviewerState:
    consecutive_approvals: int = 0
    last_action_ts: float = 0.0
    cooldown_until: float = 0.0

class ApproverRotation:
    def __init__(self, reviewers: list[str], max_consecutive: int = 5,
                 cooldown_seconds: int = 600):
        self.reviewers = reviewers
        self.max_consecutive = max_consecutive
        self.cooldown = cooldown_seconds
        self.state = {r: ReviewerState() for r in reviewers}
        self._idx = 0
        self.high_risk_threshold: float = 50_000.0   # $ — needs 2nd reviewer

    def next_reviewer(self) -> str:
        for _ in range(len(self.reviewers)):
            r = self.reviewers[self._idx % len(self.reviewers)]
            self._idx += 1
            s = self.state[r]
            if time.time() > s.cooldown_until and s.consecutive_approvals < self.max_consecutive:
                return r
        # everyone cooling down → force wait (better safe than rubber-stamped)
        raise RuntimeError("All reviewers in cooldown — mandatory pause. This is intentional.")

    def needs_secondary_review(self, amount: float) -> bool:
        return amount >= self.high_risk_threshold

    def record(self, reviewer: str, approved: bool):
        s = self.state[reviewer]
        if approved:
            s.consecutive_approvals += 1
            if s.consecutive_approvals >= self.max_consecutive:
                s.cooldown_until = time.time() + self.cooldown   # force break
        else:
            s.consecutive_approvals = 0
        s.last_action_ts = time.time()
