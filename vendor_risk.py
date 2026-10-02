"""
(7) Vendor Risk — third-party models update automatically, silently
changing your security posture. Keep critical decision logic and
final approvals in YOUR infrastructure; vendors get read-only.
"""
from __future__ import annotations
import yaml, time

class VendorRiskManager:
    def __init__(self, policy_path: str):
        with open(policy_path) as f:
            self.policy = yaml.safe_load(f).get("vendors", {})

    def approved(self, vendor: str) -> bool:
        v = self.policy.get(vendor)
        return bool(v and v.get("approved"))

    def scopes_for(self, vendor: str) -> list[str]:
        v = self.policy.get(vendor, {})
        scopes = list(v.get("read_only_scopes", []))
        if v.get("allow_write"):
            scopes += v.get("write_scopes", [])
        return scopes                                   # read-only by default

    def check_update_safety(self, vendor: str, new_version: str) -> bool:
        """Gate automatic model updates: pin allowed versions/ranges."""
        v = self.policy.get(vendor, {})
        pinned = v.get("pinned_version")
        if pinned and new_version != pinned:
            return False   # auto-update would change posture → requires human review
        return True

    def require_local_approval(self, decision_type: str) -> bool:
        """Critical decisions (payments, contracts, access grants) never
        delegate final approval to a vendor model."""
        return decision_type in set(self.policy.get("local_only_decisions",
                                    ["payment", "contract", "access_grant"]))
