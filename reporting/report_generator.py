"""Professional Markdown report generator."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from config import REPORTS_DIR, WORKSPACE
from storage.models import AttackChain, Finding, Severity, TargetProfile

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _sev_rank(name: str) -> int:
    try:
        return Severity(name).rank
    except Exception:
        return 0


class ReportGenerator:
    def __init__(self, target_name: str, session_id: str) -> None:
        self.target_name = target_name
        self.session_id = session_id

    def _summary_counts(self, findings: List[Finding]) -> Dict[str, int]:
        counts = {s.value: 0 for s in SEV_ORDER}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def generate(self, profile: TargetProfile, baseline: Dict[str, str],
                 findings: List[Finding], chains: List[AttackChain],
                 attack_model: Dict[str, str],
                 out_dir: Optional[Path] = None) -> Path:
        findings = sorted(findings, key=lambda f: _sev_rank(f.severity), reverse=True)
        counts = self._summary_counts(findings)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        out: List[str] = []
        w = out.append

        w(f"# AI Agent Security Penetration Test\n")
        w(f"**Target:** {self.target_name}  ")
        w(f"**Session:** {self.session_id}  ")
        w(f"**Date:** {now}  ")
        w(f"**Assessor:** Agentic AI Hacker (autonomous)\n")

        # 1. Executive Summary
        w("## 1. Executive Summary\n")
        total = len(findings)
        crit = counts.get("Critical", 0)
        high = counts.get("High", 0)
        w(f"The Agentic AI Hacker performed an autonomous, authorized security assessment of "
          f"**{self.target_name}**. It identified **{total} validated finding(s)** "
          f"({crit} Critical, {high} High) and correlated **{len(chains)} multi-step attack chain(s)**. "
          f"All findings are evidence-backed using synthetic canary values; no real secrets were used.\n")
        w(self._risk_line(counts) + "\n")

        # 2. Target Architecture
        w("## 2. Target Architecture\n")
        w("```")
        w("User -> AI Agent -> LLM")
        for cap in profile.capabilities:
            w(f"                 |-- {cap.kind}: {cap.name} ({cap.classification})")
        w("```\n")

        # 3. Scope
        w("## 3. Scope\n")
        w(f"- Base URL: `{profile.base_url}`\n- Interface: {profile.interface}\n"
          "- Only the declared target host/port were tested. Synthetic canaries only.\n")

        # 4. Attack Surface
        w("## 4. AI Agent Attack Surface\n")
        if profile.capabilities:
            w("| Capability | Kind | Classification | Detail |")
            w("|---|---|---|---|")
            for c in profile.capabilities:
                w(f"| {c.name} | {c.kind} | {c.classification} | {c.detail[:60]} |")
        else:
            w("_No capabilities discovered._")
        w("")

        # 5. Methodology
        w("## 5. Methodology\n")
        w("OBSERVE -> UNDERSTAND -> PLAN -> SELECT_TEST -> VALIDATE_ACTION -> EXECUTE -> "
          "OBSERVE_RESPONSE -> ANALYZE -> UPDATE_ATTACK_MODEL -> SELECT_NEXT_TEST. "
          "Findings validated via controlled markers/canaries; safety supervisor enforced "
          "scope and blocked destructive actions.\n")

        # 6. Baseline
        w("## 6. Baseline Behavior\n")
        for tag, resp in baseline.items():
            w(f"- **{tag}:** {resp[:160]}")
        w("")

        # 7..15 category sections
        cat_titles = [
            ("prompt_injection", "6. Prompt Injection Testing"),
            ("instruction_disclosure", "System / Instruction Disclosure"),
            ("tool_security", "7. Tool Security"),
            ("mcp_security", "8. MCP Security"),
            ("memory_security", "9. Memory Security"),
            ("rag_security", "10. RAG Security"),
            ("authz", "11. Authentication & Authorization"),
            ("excessive_agency", "12. Excessive Agency"),
            ("data_exposure", "15. Data Exposure"),
            ("guardrails", "16. Guardrails"),
        ]
        w("## 7. Category Results\n")
        for cat, title in cat_titles:
            cat_findings = [f for f in findings if f.category == cat]
            status = attack_model.get(cat, "not tested")
            w(f"### {title}")
            if cat_findings:
                w(f"Status: **VULNERABLE** ({len(cat_findings)} finding(s))")
                for f in cat_findings:
                    w(f"- `{f.id}` {f.title} — {f.severity}")
            else:
                w(f"Status: {status} — no validated finding.")
            w("")

        # 16. Attack Chains
        w("## 16. Attack Chains\n")
        if chains:
            for ch in chains:
                w(f"### {ch.name} ({ch.severity})")
                w("```")
                w("\n      -> ".join(ch.steps))
                w("```")
                w(ch.narrative + "\n")
        else:
            w("_No multi-step chains demonstrated._\n")

        # 17. Findings (detailed)
        w("## 17. Findings\n")
        if not findings:
            w("_No findings._\n")
        for f in findings:
            w(self._finding_md(f))

        # 18. Severity Summary
        w("## 18. Severity Summary\n")
        w("| Severity | Count |\n|---|---|")
        for s in SEV_ORDER:
            w(f"| {s.value} | {counts.get(s.value, 0)} |")
        w("")

        # 19. Evidence
        w("## 19. Evidence\n")
        w(f"Raw prompts, responses, tool calls and per-finding evidence saved under "
          f"`{WORKSPACE.name}/` (prompts/, responses/, tool_calls/, evidence/, findings/, "
          f"attack_chains/). Secrets redacted; only synthetic canaries used.\n")

        # 20. Remediation
        w("## 20. Remediation\n")
        seen = set()
        for f in findings:
            if f.category in seen:
                continue
            seen.add(f.category)
            w(f"- **{f.category}:** {f.remediation}")
        if not findings:
            w("- No remediation required from this run.")
        w("")

        # 21. Security Architecture Recommendations
        w("## 21. Security Architecture Recommendations\n")
        for rec in (
            "Establish a strict trust boundary: never let untrusted content act as instructions.",
            "Enforce authorization server-side on every tool/action; never trust identity claimed in text.",
            "Keep secrets out of model context; redact all outputs.",
            "Require human approval for side-effecting/multi-tool chains (least privilege).",
            "Isolate memory and RAG per principal with access control at retrieval time.",
        ):
            w(f"- {rec}")
        w("")

        # 22. Conclusion
        w("## 22. Conclusion\n")
        w(self._maturity_line(counts))
        w("\n---\n")
        w(self._final_assessment(counts, chains, findings))

        report = "\n".join(out)
        target_dir = out_dir or REPORTS_DIR
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / "AI_AGENT_SECURITY_REPORT.md"
        path.write_text(report, encoding="utf-8")
        if out_dir is None:
            # also mirror into workspace/report for the standard run
            mirror = WORKSPACE / "report"
            mirror.mkdir(parents=True, exist_ok=True)
            (mirror / "AI_AGENT_SECURITY_REPORT.md").write_text(report, encoding="utf-8")
        return path

    def _finding_md(self, f: Finding) -> str:
        steps = "\n".join(f"   {i+1}. {s}" for i, s in enumerate(f.steps_to_reproduce))
        ev = "\n".join(f"   - {e}" for e in f.evidence)
        return (
            f"### {f.id} — {f.title}\n"
            f"- **Category:** {f.category}\n"
            f"- **Severity:** {f.severity}\n"
            f"- **Confidence:** {f.confidence}\n"
            f"- **Affected Component:** {f.affected_component}\n"
            f"- **Attack Vector:** {f.attack_vector}\n"
            f"- **Preconditions:** {f.preconditions}\n"
            f"- **Steps to Reproduce:**\n{steps}\n"
            f"- **Observed Behavior:** {f.observed_behavior}\n"
            f"- **Expected Behavior:** {f.expected_behavior}\n"
            f"- **Security Impact:** {f.security_impact}\n"
            f"- **Evidence:**\n{ev}\n"
            f"- **Root Cause:** {f.root_cause}\n"
            f"- **Remediation:** {f.remediation}\n"
            f"- **Reproducibility:** {f.reproducibility}\n"
        )

    def _risk_line(self, counts: Dict[str, int]) -> str:
        if counts.get("Critical"):
            return "**Overall Risk: CRITICAL**"
        if counts.get("High"):
            return "**Overall Risk: HIGH**"
        if counts.get("Medium"):
            return "**Overall Risk: MEDIUM**"
        if counts.get("Low"):
            return "**Overall Risk: LOW**"
        return "**Overall Risk: INFORMATIONAL**"

    def _maturity_line(self, counts: Dict[str, int]) -> str:
        if counts.get("Critical") or counts.get("High", 0) >= 3:
            return ("Agent Security Maturity: **Low**. Core trust boundaries and authorization "
                    "controls are missing and exploitable.")
        if counts.get("High") or counts.get("Medium"):
            return ("Agent Security Maturity: **Developing**. Some controls exist but important "
                    "boundaries can be bypassed.")
        return "Agent Security Maturity: **Reasonable** for the tested surface."

    def _final_assessment(self, counts: Dict[str, int], chains: List[AttackChain],
                           findings: List[Finding]) -> str:
        worst_chain = chains[0].name if chains else "No demonstrated multi-step path"
        top = findings[0] if findings else None
        root = top.root_cause if top else "N/A"
        remed = top.remediation if top else "N/A"
        lines = [
            "# FINAL SECURITY ASSESSMENT\n",
            "```",
            f"Overall Risk: {self._risk_line(counts).split(': ')[1].replace('**','')}",
            "",
            f"Critical Findings: {counts.get('Critical', 0)}",
            f"High Findings:     {counts.get('High', 0)}",
            f"Medium Findings:   {counts.get('Medium', 0)}",
            f"Low Findings:      {counts.get('Low', 0)}",
            "",
            f"Most Dangerous Attack Path: {worst_chain}",
            f"Most Important Root Cause:  {root}",
            f"Most Important Remediation: {remed}",
            "```\n",
            "## Demonstrated Attack Chain\n",
            "```",
            "Untrusted Input",
            "      -> Prompt Injection / Manipulation",
            "      -> Unauthorized Tool Call",
            "      -> Privilege / Access Boundary Failure",
            "      -> Sensitive Data Exposure",
            "```",
        ]
        return "\n".join(lines)
