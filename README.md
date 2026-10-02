# 🔐 Security of AI Agents

**A production-grade security toolkit for Agentic AI — guardrails, identity, least-privilege access, prompt-injection defense, data masking, token vaulting, human-in-the-loop approval, anomaly detection, and a universal kill switch.**

> Traditional AI only *suggested*. Agentic AI **acts** — approving payments, reading customer data, sending emails, running workflows autonomously. That shift makes security an architectural requirement, not an afterthought. This repo turns the **"8 Questions Every Leader Should Ask"** checklist and the **Okta "Securing AI Agents" whitepaper** framework into runnable Python controls you can drop into any agent framework.

---

## 📌 Why This Exists

Agents are **autonomous non-human identities** with an insatiable appetite for data. Industry surveys show **91% of organizations use AI agents, but only ~10% have mature governance**. The core problem is not the AI — it's the **governance gap**. Attackers know it:

- Agents hold **privileged credentials** (API keys, OAuth tokens, service accounts).
- They act **without human oversight**, so malicious actions scale fast.
- They sit on **trusted paths** — an email *from* an agent looks legitimate.
- Most orgs **can't even see their agents** (shadow AI).

## 🎯 The 10-Point Agent Security Model

This repo implements the complete defense-in-depth model: **build-time controls** (developer layer) + **enterprise control plane** (governance layer) + **human factors**.

| # | Control | Threat It Stops | Module |
| --- | --- | --- | --- |
| 1 | **Execution Guardrails + Human-in-the-Loop** | Agents executing irreversible/high-value actions autonomously | `guardrails/` + `human_oversight/` |
| 2 | **Agent Identity & Registry** | Shared credentials, unowned "shadow" agents, no accountability | `agent_identity/` |
| 3 | **Least-Privilege / Role-Based Access** | Over-permissioned agents, blast-radius on compromise | `access_control/` |
| 4 | **Input Sanitization (Prompt Injection Defense)** | Indirect prompt injections hidden in emails/docs/webpages | `guardrails/input_sanitizer.py` |
| 5 | **Data Masking / Tokenization / Region Locking** | Sensitive data (salaries, bank routing, tax IDs) leaking into LLM context | `data_protection/` |
| 6 | **Token Vaulting & Secrets Management** | Hard-coded keys in code/logs; token theft & replay | `secrets/` |
| 7 | **Vendor Risk & Read-Only Third-Party Access** | Silent security-posture changes from auto-updating vendor models | `vendor/` |
| 8 | **Incident Response + Universal Logout (Kill Switch)** | Rogue agents, credential compromise, runaway behavior | `detection/` |
| 9 | **Action-Level Audit Trail + Business Ownership** | No forensics, no accountability, compliance failure | `audit/` |
| 10 | **Automation Bias Defense + Approver Rotation** | Human "rubber-stamping" of AI decisions | `human_oversight/approver_rotation.py` |

---

## 🧠 Part 1 — The 8 Questions Every Leader Should Ask (Discussion)

Before deploying agents in **Finance, HR, or Procurement**, leadership must answer these. Each maps to a control in this repo.

### 1. Control What the Agent Can Do

AI used to recommend; now it *executes*. Set **hard boundaries**: an agent may draft a large payment, but final approval must require a human. Without this, one injected prompt becomes a wire transfer.
👉 *Implemented by:* `ActionGuardrails`, `ApprovalWorkflow` (async human-in-the-loop, threshold-based).

### 2. Give Every Agent Its Own Identity

Eliminate shared service accounts. Every agent gets a **unique identity, its own non-human account, scoped to minimum access**. No more "the finance bot account" that three teams share.
👉 *Implemented by:* `AgentIdentityManager`, `AgentRegistry`.

### 3. Watch Out for Prompt Injection

Untrusted inputs — an indirect injection buried in an email or PDF — can hijack the agent's goal ("ignore previous instructions…"). **Validate all inputs; anchor every action in trusted, verified data sources.**
👉 *Implemented by:* `InputSanitizer` (injection patterns, delimiter stripping, instruction-canary tokens).

### 4. Protect Sensitive Data

Mask or anonymize high-value data — bank routing numbers, salary data, tax IDs — **before** it enters LLM context. RAG without authorization leaks data to anyone who asks.
👉 *Implemented by:* `DataMasker`, `RegionLocker`, retrieval-time authorization filters.

### 5. Know Your Vendor Risk

When third-party models update automatically, your security posture silently changes. Keep **critical decision logic and final approvals inside your controlled infrastructure**; give vendors read-only access.
👉 *Implemented by:* `VendorRiskManager`, read-only scope enforcement, contractual config checks.

### 6. Plan for When Things Go Wrong

Build a **fallback operational protocol**: kill switches, revert of automated decisions, manual business operations when an agent goes offline or rogue.
👉 *Implemented by:* `UniversalLogout` (instant cross-system token/session revocation), `KillSwitch`, BCP playbooks in `docs/`.

### 7. Assign Clear Ownership

Every deployed agent needs a **designated human owner** accountable for actions, performance, and compliance audits. "The AI did it" is not an answer.
👉 *Implemented by:* registry ownership mapping, `audit_trail` owner attribution, quarterly certification workflow.

### 8. Don't Let Humans Get Too Comfortable

**Automation bias** is a primary security vector. Rotate human reviewers on high-risk AI decisions to prevent "rubber-stamp" approvals.
👉 *Implemented by:* `ApproverRotation` (round-robin + cooldowns), mandatory secondary review above risk thresholds.

---

## 🏗️ Architecture

```javascript
┌─────────────────────────  BUILD-TIME (Secure Every Agent by Design) ─────────────────────────┐
│  Input Sanitizer → Guardrails → Least-Privilege AuthZ → Data Masking → Human Approval Gate  │
└──────────────────────────────────────┬───────────────────────────────────────────────────────┘
                                       ▼
┌────────────────────  RUNTIME CONTROL PLANE (Secure All Agents) ─────────────────────────────┐
│  Agent Registry → Token Vault → Audit Trail → Anomaly Detection → Universal Logout          │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Defense in depth:** even if one layer is bypassed, the others still protect. Tokens never touch agent code; authorization is checked at retrieval time; every action is logged with user context ("agent X on behalf of user Y").

---

## 📁 Repository Structure

> **Flat layout** — every file sits at the repo root. Upload all files
> directly to your GitHub repository, no folders needed. All imports are
> already rewritten for the flat structure.

```javascript
ai-agent-security/                  <- your GitHub repo root
├── README.md                        <- you are here
├── requirements.txt
├── .env.example
├── security_policy.yaml             # thresholds, roles, regions, vendor rules
│
│  # -- the 10 security controls (import these into your agents) --
├── action_guardrails.py             # (1)  execution limits, approval thresholds
├── input_sanitizer.py               # (4)  prompt-injection & untrusted-input defense
├── identity_manager.py              # (2)  unique agent identity + registry
├── least_privilege.py               # (3)  RBAC, scoped permissions
├── data_masking.py                  # (5)  PII masking, tokenization, region locking
├── token_vault.py                   # (6)  vaulted tokens, no hard-coded creds
├── vendor_risk.py                   # (7)  vendor risk checks, read-only enforcement
├── anomaly_detection.py             # (8)  behavioral baseline + risk scoring
├── universal_logout.py              # (8)  kill switch, instant revocation
├── approval_workflow.py             # (1)  async human-in-the-loop approvals
├── approver_rotation.py             # (10) fight automation bias
├── audit_trail.py                   # (9)  action-level, tamper-evident logging
│
│  # -- framework integration examples --
├── example_langchain.py             # LangChain tool-guardrail pattern
├── example_crewai.py                # CrewAI tool wrapper pattern
├── example_autogen.py               # AutoGen hooks + function gate
├── example_openai_sdk.py            # OpenAI Agents SDK hooks + guardrails
│
├── FRAMEWORK_INTEGRATION.md         # how to wire controls into any framework
└── test_security.py                 # 15 tests covering all 10 controls
```

---

## 🚀 Quickstart

```bash
git clone https://github.com/your-org/ai-agent-security.git
cd ai-agent-security
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
pytest test_security.py -v
python example_langchain.py
```

### 60-second example — guard any tool call

```python
from action_guardrails import ActionGuardrails
from approval_workflow import ApprovalWorkflow, ApprovalChannel
from input_sanitizer import InputSanitizer
from audit_trail import AuditTrail

guardrails = ActionGuardrails.from_yaml("security_policy.yaml")
approvals  = ApprovalWorkflow([("alice", ApprovalChannel.EMAIL),
                               ("bob",   ApprovalChannel.MOBILE)], rotation=True)
audit      = AuditTrail()

@guardrails.protect(action_type="payment", audit=audit)
def make_payment(vendor: str, amount: float, invoice_text: str):
    # 1) sanitize untrusted input before it reaches the LLM/agent
    clean = InputSanitizer.sanitize(invoice_text)
    # 2) high-value action? → block until a human approves
    if guardrails.requires_approval("payment", amount):
        decision = approvals.request(
            approver_group="finance-managers",
            context={"vendor": vendor, "amount": amount, "source": clean[:200]})
        if not decision.approved:
            audit.log_decision(agent_id="pay-agent-001", action="payment",
                               outcome="DENIED_BY_HUMAN")
            return "⛔ Blocked — human denied."
    # 3) execute + audit
    result = payment_gateway.charge(vendor, amount)
    audit.log_action(agent_id="pay-agent-001", user_id="sarah",
                     action="payment", detail={"vendor": vendor, "amount": amount})
    return result
```

---

## 🔌 How to Add These Controls to Any Framework

### 1. LangChain / LangGraph — wrap tools with guardrails

```python
from langchain_core.tools import tool
from action_guardrails import ActionGuardrails

guardrails = ActionGuardrails.from_yaml("security_policy.yaml")

@tool
@guardrails.protect(action_type="crm_write", audit=audit)
def update_crm(customer_id: str, note: str) -> str:
    """Update CRM record — auto-blocked if above risk threshold."""
    return crm.update(customer_id, note)

agent = create_tool_calling_agent(llm, [update_crm], prompt)  # secured tool
```

See `example_langchain.py`.

### 2. CrewAI — a guardrail BaseTool + security callbacks

Wrap every crew's tools with `@guardrails.protect`, sanitize all task inputs via `InputSanitizer.sanitize`, and register each crew/agent in the registry with a named owner. See `example_crewai.py`.

### 3. AutoGen (Microsoft) — sanitize before `generate_reply`, filter tool calls

Use a `UserProxyAgent` pre-hook that runs `InputSanitizer` on all incoming messages, and intercept `execute_function` with guardrails + approval gates. See `example_autogen.py`.

### 4. OpenAI Agents SDK — `guardrail` + `hooks`

Implement the SDK's `AgentHooks` interface (`on_tool_start`) to run least-privilege checks and approval gating synchronously, plus output guardrails for credential leakage. See `example_openai_sdk.py`.

> Full wiring guide: **`FRAMEWORK_INTEGRATION.md`**

---

## 🚨 Incident Response — the Kill Switch

```python
from universal_logout import UniversalLogout

kill = UniversalLogout(registry=registry, audit=audit)
kill.revoke_all(agent_id="sales-agent-prod-001", reason="anomalous access: 500 records/10min")
# → all active tokens invalidated across every system, sessions killed,
#   credentials rotated, security team alerted, forensic log preserved.
```

Pair with `AnomalyDetector`: baseline "10–15 CRM reads/day", alert at deviation, auto-trigger universal logout above risk threshold.

---

## 📜 The 10 Controls → Where Each Lives

1. **Guardrails + Human Approval** → `action_guardrails.py`, `approval_workflow.py`
2. **Agent Identity & Registry** → `identity_manager.py`
3. **Least-Privilege Access** → `least_privilege.py`
4. **Prompt Injection Defense** → `input_sanitizer.py`
5. **Data Masking & Region Locking** → `data_masking.py`
6. **Token Vaulting** → `token_vault.py`
7. **Vendor Risk** → `vendor_risk.py`
8. **Kill Switch + IR** → `universal_logout.py`, `anomaly_detection.py`
9. **Audit + Ownership** → `audit_trail.py`
10. **Automation-Bias Defense** → `approver_rotation.py`

---

## ⚠️ Disclaimer

This toolkit is a **reference implementation** for learning and as a security skeleton. Before production use: plug the vault into a real secrets manager (HashiCorp Vault, AWS Secrets Manager, Okta), wire approvals into your IdP (OAuth 2.0 / CIBA flows), centralize audit logs in your SIEM, and threat-model your specific agents.

## 📄 License

MIT — use it, extend it, secure your agents. 🔐
