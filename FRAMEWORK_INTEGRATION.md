# Framework Integration Guide

How to wire `ai-agent-security` controls into any agent framework.
All modules are **framework-agnostic** — they wrap or intercept, they
don't replace your framework.

---

## Universal Integration Rules (any framework)

1. **Register before run** — every agent must exist in `AgentRegistry` with a
   named human owner, or it is shadow AI and must be blocked.
2. **Sanitize on ingress** — every external input (email, doc, webpage, user
   message) passes through `InputSanitizer.sanitize()` BEFORE the LLM sees it.
3. **Guard every tool call** — wrap tools/actions with
   `ActionGuardrails.protect()`; check `requires_approval()` for high-value
   actions and route through `ApprovalWorkflow`.
4. **Vault all credentials** — no API key, token, or password in code, env
   files, logs, or agent output. Store handles in `TokenVault` only.
5. **Check authorization at retrieval** — RAG documents are filtered by
   `retrieval_filter()` before entering context (`data_protection`).
6. **Mask before sending** — run `DataMasker.mask()` on anything leaving your
   perimeter toward an LLM/vendor.
7. **Audit everything** — one `AuditTrail` instance shared app-wide; log
   allowed, denied, and human-approved actions.
8. **Watch behavior** — record activity in `AnomalyDetector`; on `HIGH` risk
   call `UniversalLogout.revoke_all()`.
9. **Rotate approvers** — route approvals through `ApproverRotation` to defeat
   automation bias.
10. **Gate vendor updates** — `VendorRiskManager.check_update_safety()` before
    accepting any auto-update.

---

## LangChain / LangGraph
- Wrap `@tool` functions with `@guardrails.protect(...)` (see
  `examples/01_secure_agent_langchain.py`).
- For LangGraph: put `InputSanitizer` in a pre-processing node before any LLM
  node; put `ApprovalWorkflow` as an interrupt node for high-value edges.

## CrewAI
- Wrap each crew tool with `crewai_tool_wrapper()` (Example 2).
- Sanitize `Task.description` — task inputs often come from user emails.
- Register the crew AND each agent inside it in the registry.

## Microsoft AutoGen
- `autogen_message_hook` → `UserProxyAgent.register_hook("process_message_before_send", ...)`
- `autogen_function_filter` → gate `execute_function` calls for
  `send_email` / `make_payment` / `delete_record`.

## OpenAI Agents SDK
- `SecurityHooks` → `Agent(hooks=[...])` (`on_tool_start` / `on_tool_end`).
- `InjectionInputGuardrail` → `input_guardrails=[...]`
- `SecretLeakOutputGuardrail` → `output_guardrails=[...]`

## Custom / in-house agents
- Use the decorator pattern directly — `ActionGuardrails.protect` works on any
  Python callable; `ApprovalWorkflow.request()` can call your IdP's CIBA-style
  endpoint instead of the demo auto-approve.

---

## Production hardening checklist
- [ ] Replace demo vault crypto with HashiCorp Vault / AWS Secrets Manager / Okta
- [ ] Replace demo approval auto-resolve with real IdP (Auth0/Okta CIBA, push)
- [ ] Ship `AuditTrail.export()` to your SIEM (Splunk/Datadog/ELK) via webhook
- [ ] Load policy from a signed, version-controlled `security_policy.yaml`
- [ ] Quarterly access certification: re-verify every agent's scopes & owner
- [ ] Run `pytest test_security.py` in CI on every commit
