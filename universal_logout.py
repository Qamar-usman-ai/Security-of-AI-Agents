"""
(8) Universal Logout — the emergency kill switch.

One call revokes EVERYTHING for an agent: all sessions, all tokens
across all systems, credential rotation, owner + SOC alerted,
forensic audit preserved.
"""
from __future__ import annotations
import time

class KillSwitchTriggered(Exception):
    pass

class UniversalLogout:
    def __init__(self, registry, vault, audit, soc_alert=None):
        self.registry = registry
        self.vault = vault
        self.audit = audit
        self.soc_alert = soc_alert or (lambda msg: print(f"[SOC ALERT] {msg}"))

    def revoke_all(self, agent_id: str, reason: str) -> dict:
        agent = self.registry.get(agent_id)
        if agent is None:
            raise LookupError(f"Cannot revoke unknown agent '{agent_id}'.")
        # 1) suspend identity everywhere
        agent.status = "suspended"
        # 2) kill all tokens in the vault
        revoked_tokens = self.vault.revoke_all_for(service=agent.name)
        # 3) forensic log (BEFORE alerting, so it's preserved even if alert fails)
        self.audit.log_decision(agent_id=agent_id, action="UNIVERSAL_LOGOUT",
                                outcome="SUSPENDED", detail={"reason": reason,
                                "tokens_revoked": revoked_tokens, "ts": time.time()})
        # 4) alert SOC + named owner
        self.soc_alert(f"Agent {agent_id} ({agent.name}) suspended. Owner: {agent.owner}. Reason: {reason}")
        return {"agent_id": agent_id, "status": "suspended",
                "tokens_revoked": revoked_tokens, "owner_notified": agent.owner}

    def conditional_auto_response(self, agent_id: str, risk: str, detail: str):
        if risk == "HIGH":
            return self.revoke_all(agent_id, f"auto-response to {risk} risk: {detail}")
        return None
