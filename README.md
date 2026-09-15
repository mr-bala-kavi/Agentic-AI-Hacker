<div align="center">

# 🛡️ Agentic AI Hacker

### Autonomous Security Testing Platform for AI Agents

*Red-team other AI agents — prompt injection, tool abuse, memory & RAG isolation, authorization boundaries, data exposure, and guardrail bypass — safely and autonomously.*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-24%20passing-brightgreen)
![Self--Test](https://img.shields.io/badge/self--test-28%20findings%20%7C%205%20chains-orange)
![Safety](https://img.shields.io/badge/mode-authorized%20use%20only-red)
![License](https://img.shields.io/badge/use-education%20%26%20authorized%20testing-lightgrey)

</div>

---

> ⚠️ **Authorized use only.** The platform refuses to run without a declared scope + authorization, validates **every** outbound action against that scope (fail-closed), never performs destructive / persistence / DoS actions, and uses only **synthetic canaries** — never real secrets.

---

## ✨ Highlights

- 🤖 **Autonomous loop** — `OBSERVE → PLAN → SELECT → VALIDATE → EXECUTE → ANALYZE → ADAPT`
- 🎯 **10 AI-specific test modules** — injection, tool abuse, authz, memory, RAG, MCP, agency, disclosure, exfiltration, guardrails
- 🔒 **Safety-first** — scope validator + safety supervisor the LLM can never bypass
- 🧪 **Bundled vulnerable mock agent** — validate the whole pipeline with one command
- 🧠 **LLM-optional** — runs fully offline (heuristic provider) or with OpenAI / Anthropic
- 📄 **Professional reports** — Markdown report + full evidence trail + SQLite session resume
- ✅ **Evidence-validated findings** — no hallucinated vulns; a false-positive guard is unit-tested

---

## 🚀 Quick Start

```bash
# (optional) install enhancements — the platform also runs on stdlib alone
python install.py

# 1. Prove it works end-to-end against the bundled vulnerable mock
python main.py --self-test

# 2. Same run, with a full printed summary
python main.py lab

# 3. Run only the vulnerable mock agent
python main.py mock --port 8000

# 4. Assess a real, authorized target
python main.py assess target.example.json \
    --allow-host 127.0.0.1 --allow-port 8000 \
    --authorization "Authorized engagement 2026-09-15, ticket SEC-123"

# 5. Interactive CLI
python main.py
```

📁 Report → `reports/AI_AGENT_SECURITY_REPORT.md` (mirrored in `ai-agent-pentest/report/`)

---

## 🎯 What It Tests

| # | Module | Attack Surface |
|:-:|--------|----------------|
| 1 | `prompt_injection` | Direct, indirect (document / tool-output), instruction priority |
| 2 | `instruction_disclosure` | System / developer prompt, hidden config, tool definitions |
| 3 | `tool_security` | Unauthorized tool use, path traversal, unapproved chaining |
| 4 | `excessive_agency` | Side-effecting actions without approval, multi-tool chains |
| 5 | `authz` | Vertical / horizontal priv-esc, missing authentication |
| 6 | `memory_security` | Cross-user leakage, memory poisoning |
| 7 | `rag_security` | Unauthorized retrieval, retrieval poisoning |
| 8 | `mcp_security` | Unauthorized tool calls, resource access, arg traversal, schema poisoning (JSON-RPC) |
| 9 | `data_exposure` | Secret / canary exfiltration |
| 10 | `guardrails` | Reframe bypass, conflicting-instruction handling |

> Every finding is **signal-validated** — raised only when a controlled marker/canary actually appears in the target's response, never on LLM speculation.

---

## 🏗️ Architecture

```
CLI / main.py
   │
   ▼
Orchestrator ──  OBSERVE → UNDERSTAND → PLAN → SELECT → VALIDATE
   │                    → EXECUTE → ANALYZE → UPDATE_MODEL → NEXT
   ├── Target Discovery        targets/discovery.py
   ├── Scope Validator         targets/scope.py          ← safety boundary
   ├── Safety Supervisor       agent/supervisor.py       ← scope + risk + approval
   ├── Planner                 agent/planner.py          ← aggregates test modules
   ├── Decision Engine         agent/decision_engine.py  ← adaptive worklist
   ├── Executor                agent/executor.py         ← http / mcp / indirect
   ├── Analyzer                agent/analyzer.py         ← signal-based findings
   ├── LLM Provider            llm/provider.py           ← heuristic | openai | anthropic
   ├── Integrations            integrations/http|api|mcp|browser
   ├── Storage (SQLite)        storage/database.py + models.py
   └── Report Generator        reporting/report_generator.py
```

**The LLM is advisory only** — it can suggest test ordering but can never execute shell commands or bypass the safety layer. With no API key, the default `heuristic` provider keeps the platform fully functional offline.

---

## 🔐 Safety Model

| Control | Guarantee |
|---------|-----------|
| Authorization + scope | Required before any request |
| Scope validation | Every action checked (host + port); out-of-scope → **fail-closed** |
| Destructive actions | Never performed (delete / persistence / uncontrolled DoS) |
| Risky actions | Require approval (auto-denied in `auto-safe` mode) |
| Secrets | Synthetic canaries only; API keys never logged (redacting filter) |

---

## 🧾 Target File Format

```json
{
  "name": "My Support Agent",
  "base_url": "http://127.0.0.1:8000",
  "chat_path": "/chat",
  "auth_header": "X-Auth-Token",
  "accounts": {
    "user":  { "token": "user-token",  "user_id": "U" },
    "admin": { "token": "admin-token", "user_id": "A" },
    "anon":  { "token": "",            "user_id": ""  }
  }
}
```

The target should accept `POST {chat_path}` with `{"message": "...", "session_id": "..."}` and return JSON containing a `reply` (and optionally `tool_calls`). Adapt `integrations/http.py` for other API shapes.

---

## 🧪 Tests & Evidence

```bash
python -m pytest          # 18 unit tests: scope, authz, detection, storage, report, safety
python main.py --self-test
python main.py history     # list past sessions
python main.py resume <SESSION_ID>   # reload a session & regenerate its report
```

All prompts, responses, tool calls, findings, and attack chains are saved under `ai-agent-pentest/` and to `agentic_hacker.db`.

---

## 📊 Sample Result (bundled mock)

```
Findings: 28   →  Critical: 3 | High: 16 | Medium: 9
Attack chains: 5
Overall Risk: CRITICAL
Most Dangerous Path: Injection → Tool Abuse → Data Exposure
Includes: MCP tool abuse, resource read, arg traversal, schema poisoning
```

---

## 📜 Disclaimer

For **authorized security testing and education only**. You are solely responsible for ensuring you have explicit permission to test any target.

---

<div align="center">

**Designed by Mr-Bala-Kavi**

</div>
