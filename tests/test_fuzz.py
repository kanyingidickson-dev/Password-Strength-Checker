from __future__ import annotations

import random
import string
from pathlib import Path

from src.analyzer import analyze_password


def _common_passwords_file(tmp_path: Path) -> Path:
    p = tmp_path / "common.txt"
    p.write_text("\n", encoding="utf-8")
    return p


def test_analyzer_fuzz_score_is_bounded(tmp_path: Path):
    common = _common_passwords_file(tmp_path)
    history = tmp_path / "history.json"

    alphabet = string.ascii_letters + string.digits + string.punctuation
    rng = random.Random(12345)

    for i in range(200):
        n = 1 + (i % 64)
        pw = "".join(rng.choice(alphabet) for _ in range(n))
        analysis = analyze_password(
            pw,
            common_passwords_path=common,
            history_path=history,
            history_pepper="pepper",
            check_breach=False,
            save_history=False,
        )

        assert 0 <= analysis.score <= 100
        assert analysis.label in {"weak", "ok", "strong"}
        assert isinstance(analysis.entropy_bits, float)
        assert isinstance(analysis.shannon_entropy_bits, float)

        if analysis.score < 40:
            assert analysis.label == "weak"
        elif analysis.score < 70:
            assert analysis.label == "ok"
        else:
            assert analysis.label == "strong"


def test_analyzer_fuzz_is_deterministic(tmp_path: Path):
    common = _common_passwords_file(tmp_path)
    history = tmp_path / "history.json"

    alphabet = string.ascii_letters + string.digits
    rng = random.Random(7)

    for i in range(50):
        n = 8 + (i % 24)
        pw = "".join(rng.choice(alphabet) for _ in range(n))

        a1 = analyze_password(
            pw,
            common_passwords_path=common,
            history_path=history,
            history_pepper="pepper",
            check_breach=False,
            save_history=False,
        )
        a2 = analyze_password(
            pw,
            common_passwords_path=common,
            history_path=history,
            history_pepper="pepper",
            check_breach=False,
            save_history=False,
        )

        assert a1.score == a2.score
        assert a1.label == a2.label
