from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from src.analyzer import analyze_password


def _common_passwords_file(tmp_path: Path) -> Path:
    p = tmp_path / "common.txt"
    p.write_text("\n", encoding="utf-8")
    return p


def test_analyzer_breach_unavailable_does_not_change_score(tmp_path: Path):
    common = _common_passwords_file(tmp_path)
    history = tmp_path / "history.json"

    baseline = analyze_password(
        "CorrectHorseBatteryStaple",
        common_passwords_path=common,
        history_path=history,
        history_pepper="pepper",
        check_breach=False,
        save_history=False,
    )

    with patch("src.analyzer.check_pwned_password_k_anonymity", return_value=None):
        analysis = analyze_password(
            "CorrectHorseBatteryStaple",
            common_passwords_path=common,
            history_path=history,
            history_pepper="pepper",
            check_breach=True,
            save_history=False,
        )

    assert analysis.breach_count is None
    assert "Breach check unavailable (network error)" in analysis.reasons
    assert analysis.score == baseline.score


def test_analyzer_breach_not_found_adds_small_bonus(tmp_path: Path):
    common = _common_passwords_file(tmp_path)
    history = tmp_path / "history.json"

    baseline = analyze_password(
        "CorrectHorseBatteryStaple",
        common_passwords_path=common,
        history_path=history,
        history_pepper="pepper",
        check_breach=False,
        save_history=False,
    )

    with patch("src.analyzer.check_pwned_password_k_anonymity", return_value=0):
        analysis = analyze_password(
            "CorrectHorseBatteryStaple",
            common_passwords_path=common,
            history_path=history,
            history_pepper="pepper",
            check_breach=True,
            save_history=False,
        )

    assert analysis.breach_count == 0
    assert "Not found in breach corpus (k-anonymity check)" in analysis.reasons
    assert analysis.score == min(100, baseline.score + 5)


def test_analyzer_breach_found_penalizes_score(tmp_path: Path):
    common = _common_passwords_file(tmp_path)
    history = tmp_path / "history.json"

    baseline = analyze_password(
        "CorrectHorseBatteryStaple",
        common_passwords_path=common,
        history_path=history,
        history_pepper="pepper",
        check_breach=False,
        save_history=False,
    )

    with patch("src.analyzer.check_pwned_password_k_anonymity", return_value=10):
        analysis = analyze_password(
            "CorrectHorseBatteryStaple",
            common_passwords_path=common,
            history_path=history,
            history_pepper="pepper",
            check_breach=True,
            save_history=False,
        )

    assert analysis.breach_count == 10
    assert "Found in breach corpus (10 occurrences)" in analysis.reasons
    assert analysis.score == max(0, baseline.score - 50)
