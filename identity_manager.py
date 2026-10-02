"""
(2) Agent Identity & Registry — no shared credentials, no shadow AI.

Every agent gets: unique persistent ID, its own credential set,
named human owner, documented purpose. Mirrors the Okta control
plane's Agent Registry concept.
"""
from __future__ import annotations
import uuid, time, json
from dataclasses import dataclass, field, asdict

@dataclass
class AgentIdentity:
    agent_id: str
    name: str
    owner: str                      # NAMED HUMAN — accountable for actions & audits
    purpose: str
    scopes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    status: str = "active"          # active | suspended | retired
    credential_fingerprint: str = ""  # hash of the agent's own credential — never the secret itself

class AgentRegistry:
    """Single source of truth for all agents — kills shadow AI."""

    def __init__(self):
        self._agents: dict[str, AgentIdentity] = {}

    def register(self, name: str, owner: str, purpose: str, scopes: list[str]) -> AgentIdentity:
        if not owner:
            raise ValueError("Every agent MUST have a named human owner (Question 7).")
        agent = AgentIdentity(
            agent_id=f"{name}-{uuid.uuid4().hex[:8]}",
            name=name, owner=owner, purpose=purpose, scopes=scopes,
            credential_fingerprint=uuid.uuid4().hex)
        self._agents[agent.agent_id] = agent
        return agent

    def get(self, agent_id: str) -> AgentIdentity | None:
        return self._agents.get(agent_id)

    def list_all(self) -> list[AgentIdentity]:
        return list(self._agents.values())

    def assert_active(self, agent_id: str) -> AgentIdentity:
        a = self._agents.get(agent_id)
        if a is None:
            raise LookupError(f"Unknown agent '{agent_id}' — possible SHADOW AI. Register it first.")
        if a.status != "active":
            raise PermissionError(f"Agent '{agent_id}' is {a.status}.")
        return a

    def export_manifest(self, path: str):
        with open(path, "w") as f:
            json.dump([asdict(a) for a in self._agents.values()], f, indent=2)
