"""
(5) Data Protection — Masking / Tokenization / Region Locking.

High-value data (bank routing, salaries, tax IDs) must be masked or
tokenized BEFORE entering LLM context. Access restricted by region.
"""
from __future__ import annotations
import re, hashlib

class DataMasker:
    PATTERNS = {
        "ssn":        (r"\b\d{3}-\d{2}-\d{4}\b", "***-**-****"),
        "credit_card":(r"\b(?:\d[ -]*?){13,16}\b", "****-****-****-****"),
        "bank_routing":(r"\b\d{9}\b(?=\s*(?:routing|aba))", "*********"),
        "email":      (r"([\w.+-]+)@([\w-]+\.[\w.]+)", r"\1@[masked]"),
        "salary_usd": (r"\$\s?\d{1,3}(?:,\d{3})+", "$[MASKED_SALARY]"),
        "phone":      (r"\b\+?\d[\d -]{8,}\d\b", "[MASKED_PHONE]"),
    }

    def __init__(self):
        self._token_store: dict[str, str] = {}   # token -> original (kept OUTSIDE LLM context)

    def mask(self, text: str, tokenize: bool = False) -> str:
        for _, (pat, repl) in self.PATTERNS.items():
            text = re.sub(pat, repl, text)
        return text

    def tokenize(self, value: str) -> str:
        """Replace sensitive value with a reversible vault token."""
        token = "tok_" + hashlib.sha256(value.encode()).hexdigest()[:16]
        self._token_store[token] = value
        return token

    def detokenize(self, token: str) -> str | None:
        return self._token_store.pop(token, None)   # one-time use

class RegionLocker:
    """Data residency: agents may only touch data in approved regions."""
    def __init__(self, allowed_regions: set[str]):
        self.allowed = allowed_regions

    def check(self, data_region: str, request_origin: str) -> bool:
        return data_region in self.allowed

    def enforce(self, data_region: str, request_origin: str):
        if not self.check(data_region, request_origin):
            raise PermissionError(f"Access denied: data in '{data_region}' is region-locked.")

def retrieval_filter(docs: list[dict], user_perms: set[str]) -> list[dict]:
    """RAG security: filter documents BEFORE they enter agent context."""
    return [d for d in docs if d.get("acl", "public") in user_perms or d.get("acl") == "public"]
