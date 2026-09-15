"""Optional installer: sets up dirs and (optionally) installs enhancements."""
from __future__ import annotations
import subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def main() -> int:
    for d in ("evidence", "logs", "reports", "prompts", "ai-agent-pentest"):
        (ROOT / d).mkdir(parents=True, exist_ok=True)
    print("[install] directories ready")
    if "--with-optional" in sys.argv:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r",
                                   str(ROOT / "requirements.txt")])
        except Exception as exc:
            print(f"[install] optional deps failed (platform still works): {exc}")
    print("[install] done. Try: python main.py --self-test")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
