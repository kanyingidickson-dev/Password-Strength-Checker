from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from src.analyzer import analyze_password


def main() -> int:
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--password", help="Password to analyze")
    parser.add_argument("--check-breach", action="store_true", help="Use HIBP k-anonymity API")
    parser.add_argument("--save-history", action="store_true", help="Save digest to local history")
    parser.add_argument("--json", action="store_true", help="Print analysis JSON (for automation)")
    args = parser.parse_args()

    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")

    history_path = Path(os.getenv("PASSWORD_HISTORY_PATH", "data/history.json"))
    pepper = os.getenv("PASSWORD_HISTORY_PEPPER")
    if not pepper:
        pepper = ""

    if args.save_history and not pepper:
        raise SystemExit("PASSWORD_HISTORY_PEPPER must be set to use history tracking")

    common_passwords_path = Path("data/common_passwords.txt")

    analysis = analyze_password(
        password,
        common_passwords_path=common_passwords_path,
        history_path=history_path,
        history_pepper=pepper,
        check_breach=args.check_breach,
        save_history=args.save_history,
    )

    if args.json:
        payload = {
            "score": analysis.score,
            "label": analysis.label,
            "entropy_bits": analysis.entropy_bits,
            "shannon_entropy_bits": analysis.shannon_entropy_bits,
            "is_reused": analysis.is_reused,
            "breach_count": analysis.breach_count,
            "reasons": analysis.reasons,
        }
        print(json.dumps(payload, indent=2) + "\n")
        return 0

    print(f"score: {analysis.score}/100")
    print(f"label: {analysis.label}")
    print(f"entropy_bits: {analysis.entropy_bits:.1f}")
    print(f"shannon_entropy_bits: {analysis.shannon_entropy_bits:.1f}")
    if analysis.breach_count is not None:
        print(f"breach_count: {analysis.breach_count}")
    print("reasons:")
    for r in analysis.reasons:
        print(f"- {r}")

    return 0


def cli() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
