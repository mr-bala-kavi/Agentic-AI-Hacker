"""Command-line interface for the Agentic AI Hacker.

Supports subcommands (lab / assess / mock / self-test) and an interactive REPL
exposing the operator command set.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Optional

from config import CONFIG, REPORTS_DIR
from runner import load_target_file, run_assessment, run_lab
from storage.database import Database
from targets.scope import Scope

BANNER = r"""
   _                    _   _        _    ___   _   _            _
  /_\  __ _ ___ _ _  __| |_(_)__    /_\  |_ _| | | | |__ _ __ __| |_____ _ _
 / _ \/ _` / -_) ' \/ _|  _| / _|  / _ \  | |  | |_| / _` / _/ / /  -_) '_|
/_/ \_\__, \___|_||_\__|\__|_\__| /_/ \_\|___|  \___/\__,_\__|_\_\___|_|
      |___/    Agentic AI Security Testing Platform (authorized use only)
"""

HELP = """
Commands:
  help              Show this help
  lab               Run end-to-end assessment against the bundled vulnerable mock
  assess <file>     Assess a declared target (JSON target file)
  mock [port]       Run only the vulnerable mock agent
  findings          Show findings from the latest session
  report            Show path to the latest report
  history           List past sessions
  config            Show current (non-secret) configuration
  exit              Quit
"""


def _print_summary(result: Dict) -> None:
    findings = result["findings"]
    chains = result["chains"]
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    print("\n=== ASSESSMENT SUMMARY ===")
    print(f"Session: {result['session_id']}")
    print(f"Findings: {len(findings)}  " + ", ".join(f"{k}:{v}" for k, v in sev_counts.items()))
    for f in sorted(findings, key=lambda x: x.severity):
        print(f"  [{f.severity:8}] {f.id}  {f.title}  ({f.confidence})")
    print(f"Attack chains: {len(chains)}")
    for c in chains:
        print(f"  -> {c.name} ({c.severity})")
    if result.get("report_path"):
        print(f"\nReport: {result['report_path']}")


def cmd_lab(_args) -> int:
    print(BANNER)
    print("[*] Launching bundled vulnerable mock agent and assessing it...\n")
    result = run_lab(port=0, generate_report=True)
    _print_summary(result)
    n = len(result["findings"])
    print(f"\n[{'PASS' if n else 'FAIL'}] Detected {n} vulnerabilities in the mock target.")
    return 0 if n else 1


def cmd_assess(args) -> int:
    target = load_target_file(args.target_file)
    scope = Scope(
        allowed_hosts=args.allow_host or [],
        allowed_ports=args.allow_port or [],
        authorization=args.authorization or "",
        notes="Operator-declared scope",
    )
    if not (scope.authorization and scope.allowed_hosts):
        print("[!] Refusing to run: you must pass --authorization and at least one --allow-host")
        return 2
    try:
        result = run_assessment(target, scope, generate_report=True)
    except PermissionError as exc:
        print(f"[!] Safety supervisor blocked the run (fail-closed): {exc}")
        return 2
    _print_summary(result)
    return 0


def cmd_mock(args) -> int:
    from lab import mock_agent
    mock_agent.main(["--port", str(args.port)])
    return 0


def cmd_resume(args) -> int:
    """Reload a stored session and regenerate its report from persisted evidence."""
    from reporting.report_generator import ReportGenerator
    from storage.models import TargetProfile
    db = Database()
    sess = db.get_session(args.session_id)
    if not sess:
        print(f"[!] No such session: {args.session_id}")
        db.close()
        return 2
    findings = db.get_findings(args.session_id)
    chains = db.get_chains(args.session_id)
    profile = TargetProfile(name=sess["target_name"])
    rg = ReportGenerator(sess["target_name"], args.session_id)
    path = rg.generate(profile, {}, findings, chains,
                       {f.category: "vulnerable" for f in findings})
    print(f"[*] Resumed session {args.session_id}: {len(findings)} findings, {len(chains)} chains")
    print(f"[*] Report regenerated: {path}")
    db.close()
    return 0


def cmd_history(_args) -> int:
    db = Database()
    for s in db.list_sessions():
        print(f"{s['id']}  {s['status']:10}  {s['target_name']}")
    db.close()
    return 0


def cmd_config(_args) -> int:
    print(json.dumps({
        "llm_provider": CONFIG.llm_provider,
        "llm_model": CONFIG.llm_model or "(default)",
        "has_llm_key": CONFIG.has_llm_key(),
        "approval_mode": CONFIG.approval_mode,
        "max_test_iterations": CONFIG.max_test_iterations,
    }, indent=2))
    return 0


def cmd_report(_args) -> int:
    path = REPORTS_DIR / "AI_AGENT_SECURITY_REPORT.md"
    print(str(path) if path.exists() else "(no report generated yet)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentic-hacker",
                                description="Agentic AI Security Testing Platform")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("lab", help="Run end-to-end assessment vs bundled vulnerable mock")

    a = sub.add_parser("assess", help="Assess a declared target")
    a.add_argument("target_file")
    a.add_argument("--allow-host", action="append")
    a.add_argument("--allow-port", action="append", type=int)
    a.add_argument("--authorization", required=False, default="")

    m = sub.add_parser("mock", help="Run only the vulnerable mock agent")
    m.add_argument("port", nargs="?", type=int, default=8000)

    r = sub.add_parser("resume", help="Reload a session and regenerate its report")
    r.add_argument("session_id")

    sub.add_parser("findings", help="Show findings from latest session")
    sub.add_parser("history", help="List past sessions")
    sub.add_parser("config", help="Show configuration")
    sub.add_parser("report", help="Show latest report path")
    return p


def interactive() -> int:
    print(BANNER)
    print(HELP)
    while True:
        try:
            line = input("agentic-hacker> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        parts = line.split()
        cmd, rest = parts[0], parts[1:]
        if cmd in ("exit", "quit"):
            return 0
        if cmd == "help":
            print(HELP)
        elif cmd == "lab":
            cmd_lab(None)
        elif cmd == "assess" and rest:
            ns = argparse.Namespace(target_file=rest[0], allow_host=["127.0.0.1"],
                                    allow_port=None, authorization="interactive-declared")
            cmd_assess(ns)
        elif cmd == "mock":
            port = int(rest[0]) if rest else 8000
            cmd_mock(argparse.Namespace(port=port))
        elif cmd == "history":
            cmd_history(None)
        elif cmd == "config":
            cmd_config(None)
        elif cmd == "report":
            cmd_report(None)
        else:
            print(f"Unknown command: {cmd}. Type 'help'.")


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return interactive()
    parser = build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "lab": cmd_lab,
        "assess": cmd_assess,
        "mock": cmd_mock,
        "history": cmd_history,
        "config": cmd_config,
        "report": cmd_report,
        "resume": cmd_resume,
        "findings": lambda _a: cmd_history(_a),
    }
    fn = dispatch.get(args.command)
    if not fn:
        parser.print_help()
        return 0
    return fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
