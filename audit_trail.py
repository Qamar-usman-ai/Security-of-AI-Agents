"""
(9) Action-Level Audit Trail — every action attributed to
'agent X on behalf of user Y', tamper-evident, exportable to SIEM.
"""
from __future__ import annotations
import time, json, hashlib
from dataclasses import dataclass, asdict

@dataclass
class AuditEvent:
    ts: float
    agent_id: str
    user_id: str | None
    action: str
    outcome: str            # ALLOWED | DENIED | DENIED_BY_HUMAN | ERROR
    detail: dict
    prev_hash: str
    event_hash: str

class AuditTrail:
    """Append-only, hash-chained log — tamper-evident by construction."""

    def __init__(self):
        self._events: list[AuditEvent] = []
        self._last_hash = "GENESIS"

    def _append(self, agent_id: str, user_id, action: str, outcome: str, detail: dict):
        prev = self._last_hash
        ts = time.time()                                   # single timestamp for hash + record
        payload = json.dumps({"ts": ts, "agent_id": agent_id, "user_id": user_id,
                              "action": action, "outcome": outcome, "detail": detail,
                              "prev": prev}, sort_keys=True)
        h = hashlib.sha256(payload.encode()).hexdigest()
        self._events.append(AuditEvent(ts, agent_id, user_id, action, outcome, detail, prev, h))
        self._last_hash = h

    def log_action(self, agent_id, action, user_id=None, detail=None):
        self._append(agent_id, user_id, action, "ALLOWED", detail or {})

    def log_denial(self, agent_id, action, user_id=None, detail=None):
        self._append(agent_id, user_id, action, "DENIED", detail or {})

    def log_decision(self, agent_id, action, outcome, user_id=None, detail=None):
        self._append(agent_id, user_id, action, outcome, detail or {})

    def verify_integrity(self) -> bool:
        prev = "GENESIS"
        for e in self._events:
            payload = json.dumps({"ts": e.ts, "agent_id": e.agent_id, "user_id": e.user_id,
                                  "action": e.action, "outcome": e.outcome,
                                  "detail": e.detail, "prev": prev}, sort_keys=True)
            if e.prev_hash != prev or hashlib.sha256(payload.encode()).hexdigest() != e.event_hash:
                return False                       # chain broken OR content tampered
            prev = e.event_hash
        return True

    def export(self, path: str | None = None) -> str:
        data = json.dumps([asdict(e) for e in self._events], indent=2)
        if path:
            with open(path, "w") as f:
                f.write(data)
        return data

    def by_agent(self, agent_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.agent_id == agent_id]
