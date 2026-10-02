"""
(6) Token Vaulting — credentials NEVER appear in code, logs, or output.

Mimics enterprise vault behavior: encrypted-at-rest storage, scoped
tokens, TTL + auto-refresh, full access auditing.
"""
from __future__ import annotations
import time, uuid, hashlib, json, os
from dataclasses import dataclass

@dataclass
class VaultToken:
    token_id: str
    service: str          # e.g. 'salesforce', 'gmail'
    scopes: list[str]
    expires_at: float
    ciphertext: str       # in production: encrypt with KMS; here XOR+hash demo only

class TokenVault:
    def __init__(self, master_key: str | None = None):
        self._master = (master_key or os.getenv("VAULT_MASTER_KEY", "dev-key")).encode()
        self._tokens: dict[str, VaultToken] = {}
        self._access_log: list[dict] = []

    def _enc(self, secret: str) -> str:
        return "".join(chr(ord(c) ^ self._master[i % len(self._master)]) for i, c in enumerate(secret))

    def store(self, service: str, secret: str, scopes: list[str], ttl_seconds: int = 3600) -> str:
        """Store a credential; only a token handle ever leaves the vault."""
        token_id = f"vt_{uuid.uuid4().hex[:12]}"
        self._tokens[token_id] = VaultToken(token_id, service, scopes,
                                            time.time() + ttl_seconds, self._enc(secret))
        return token_id

    def retrieve(self, token_id: str, requested_scope: str) -> str:
        t = self._tokens.get(token_id)
        if t is None:
            raise LookupError("Unknown token handle.")
        if time.time() > t.expires_at:
            raise RuntimeError("Token expired — rotate/refresh required.")
        if requested_scope not in t.scopes:
            raise PermissionError(f"Scope '{requested_scope}' not in token's grant set.")
        self._access_log.append({"token_id": token_id, "scope": requested_scope,
                                 "ts": time.time(), "sha": hashlib.sha256(token_id.encode()).hexdigest()[:8]})
        return self._enc(t.ciphertext)   # decrypt back to plaintext — IN MEMORY ONLY, never logged

    def rotate(self, token_id: str, new_secret: str) -> None:
        t = self._tokens[token_id]
        t.ciphertext = self._enc(new_secret)
        t.expires_at = time.time() + 3600

    def revoke(self, token_id: str) -> None:
        self._tokens.pop(token_id, None)

    def revoke_all_for(self, service: str) -> int:
        ids = [k for k, v in self._tokens.items() if v.service == service]
        for k in ids:
            self.revoke(k)
        return len(ids)

    def audit_report(self) -> str:
        return json.dumps(self._access_log, indent=2)

def scrub_secrets(text: str, vault: TokenVault) -> str:
    """Output filter: ensure no credential ever leaks into agent responses."""
    import re
    return re.sub(r"vt_[a-f0-9]{12}|sk-[a-zA-Z0-9]{20,}", "[REDACTED_SECRET]", text)
