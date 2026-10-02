"""
(8) Behavioral Anomaly Detection — baselines per agent, risk scoring.

Example: agent normally reads 10-15 CRM records/day. 500 records in
10 minutes => HIGH risk => trigger universal logout.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from collections import deque

@dataclass
class BehaviorBaseline:
    metric: str
    avg: float
    max_deviation_factor: float = 5.0

class AnomalyDetector:
    def __init__(self):
        self.baselines: dict[str, BehaviorBaseline] = {}
        self.events: dict[str, deque] = {}

    def set_baseline(self, agent_id: str, metric: str, avg: float, factor: float = 5.0):
        self.baselines[f"{agent_id}:{metric}"] = BehaviorBaseline(metric, avg, factor)
        self.events[f"{agent_id}:{metric}"] = deque(maxlen=1000)

    def record(self, agent_id: str, metric: str, value: float = 1.0):
        key = f"{agent_id}:{metric}"
        self.events.setdefault(key, deque(maxlen=1000)).append((time.time(), value))

    def risk_score(self, agent_id: str, metric: str, window_seconds: int = 600) -> str:
        """Return NORMAL | ELEVATED | HIGH based on deviation from baseline."""
        key = f"{agent_id}:{metric}"
        b = self.baselines.get(key)
        if not b:
            return "NORMAL"
        now = time.time()
        recent = sum(v for t, v in self.events[key] if now - t < window_seconds)
        window_avg = b.avg * (window_seconds / 86400)          # scale daily avg to window
        if recent <= window_avg * b.max_deviation_factor:
            return "NORMAL"
        if recent <= window_avg * b.max_deviation_factor * 3:
            return "ELEVATED"
        return "HIGH"                                          # e.g. 500 reads / 10 min
