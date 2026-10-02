"""
Example 2 — Securing a CrewAI crew.
Pattern: sanitize every task input, wrap tools with guardrails,
register each crew member with a named owner.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from input_sanitizer import InputSanitizer
from identity_manager import AgentRegistry
from approval_workflow import ApprovalWorkflow, ApprovalChannel
from action_guardrails import ActionGuardrails
from audit_trail import AuditTrail

registry   = AgentRegistry()
audit      = AuditTrail()
guardrails = ActionGuardrails.from_yaml("security_policy.yaml")
approvals  = ApprovalWorkflow([("finance.manager", ApprovalChannel.MOBILE),
                               ("finance.director", ApprovalChannel.EMAIL)], rotation=True)

crew_member = registry.register(name="procurement-analyst", owner="procurement.lead@company.com",
                                purpose="Vendor research and order drafting",
                                scopes=["vendor:read", "order:draft"])

def crewai_tool_wrapper(fn, action_type="generic"):
    """Wrap any CrewAI tool function with guardrails + sanitization."""
    @guardrails.protect(action_type=action_type, audit=audit)
    def wrapped(**kwargs):
        for k, v in kwargs.items():
            if isinstance(v, str):
                kwargs[k] = InputSanitizer.sanitize(v)
        return fn(**kwargs)
    return wrapped

# Usage sketch (requires crewai package):
#   from crewai import Agent, Task
#   agent = Agent(role="Procurement Analyst", tools=[crewai_tool_wrapper(search_vendors)])
#   task  = Task(description=InputSanitizer.sanitize(raw_user_email), agent=agent)

if __name__ == "__main__":
    print("Registered:", crew_member.agent_id, "owner:", crew_member.owner)
    print("Approval flow ready with rotation:", approvals.rotation)
    print("Pattern ready — plug into your Crew object.")
