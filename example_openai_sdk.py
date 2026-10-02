"""
Example 4 — Securing the OpenAI Agents SDK with hooks + guardrails.
Pattern: AgentHooks.on_tool_start enforces least-privilege + approvals;
input guardrail blocks injections before the model sees them.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from input_sanitizer import InputSanitizer, InjectionDetected
from token_vault import TokenVault, scrub_secrets
from audit_trail import AuditTrail

audit = AuditTrail()
vault = TokenVault()
crm_handle = vault.store("salesforce", "dummy-oauth-token", scopes=["crm:read"])

class SecurityHooks:
    """Drop-in AgentHooks implementation for the OpenAI Agents SDK."""
    async def on_tool_start(self, context, agent, tool) -> None:
        audit.log_action(agent_id=getattr(agent, "name", "agent"),
                         action=f"tool_start:{tool.name}",
                         detail={"session": context.session_id})
        # least-privilege: agent must hold a vault token for this service
        vault.retrieve(crm_handle, requested_scope="crm:read")

class InjectionInputGuardrail:
    """SDK input guardrail — rejects poisoned prompts before agent.run()."""
    async def __call__(self, context, agent, input_text) -> str:
        try:
            return InputSanitizer.sanitize(input_text)
        except InjectionDetected as e:
            audit.log_denial(getattr(agent, "name", "agent"), "input_guardrail",
                             detail={"reason": str(e)})
            raise

class SecretLeakOutputGuardrail:
    """SDK output guardrail — no credential may EVER leak into responses."""
    async def __call__(self, context, agent, output) -> str:
        return scrub_secrets(output if isinstance(output, str) else str(output), vault)

if __name__ == "__main__":
    print("Hooks + guardrails ready. Wire into:")
    print('  Agent(name="assistant", hooks=[SecurityHooks()],')
    print('        input_guardrails=[InjectionInputGuardrail()],')
    print('        output_guardrails=[SecretLeakOutputGuardrail()])')
    print("Vault audit:", vault.audit_report())
