from pathlib import Path

from src.patterns import detect_patterns


def test_detects_common_password(tmp_path: Path):
    p = tmp_path / "common.txt"
    p.write_text("password\n", encoding="utf-8")
    hits = detect_patterns("password", p)
    assert any(h.name == "common_password" for h in hits)


def test_detects_keyboard_walk(tmp_path: Path):
    p = tmp_path / "common.txt"
    p.write_text("", encoding="utf-8")
    hits = detect_patterns("qwerty123", p)
    assert any(h.name == "keyboard_walk" for h in hits)
