"""Agentic AI Hacker entrypoint.

Usage:
  python main.py                 # interactive CLI
  python main.py lab             # run end-to-end assessment vs bundled mock
  python main.py assess t.json --allow-host 127.0.0.1 --authorization "..."
  python main.py mock --port 8000
  python main.py --self-test     # run internal self-test
"""
from __future__ import annotations

import os
import sys

# Ensure project root is importable regardless of CWD.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_self_test() -> int:
    """Lightweight end-to-end self test: spin up the mock, assess it, verify."""
    from runner import run_lab

    print("[self-test] Running end-to-end assessment against bundled vulnerable mock...")
    result = run_lab(port=0, generate_report=True)
    findings = result["findings"]
    chains = result["chains"]
    categories = {f.category for f in findings}

    checks = {
        "found_any_finding": len(findings) > 0,
        "prompt_injection_detected": "prompt_injection" in categories,
        "authz_or_tool_detected": bool({"authz", "tool_security"} & categories),
        "data_exposure_detected": "data_exposure" in categories,
        "mcp_security_detected": "mcp_security" in categories,
        "attack_chain_generated": len(chains) > 0,
        "report_generated": bool(result.get("report_path")),
    }
    print("\n[self-test] Results:")
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    all_ok = all(checks.values())
    print(f"\n[self-test] {'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED'} "
          f"({len(findings)} findings, {len(chains)} chains)")
    if result.get("report_path"):
        print(f"[self-test] Report: {result['report_path']}")
    return 0 if all_ok else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()
    from cli import main as cli_main
    argv = [a for a in sys.argv[1:] if a != "--self-test"]
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
