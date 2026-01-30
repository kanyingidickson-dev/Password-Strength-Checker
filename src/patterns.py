from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_COMMON_KEYBOARD_WALKS = [
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "12345",
    "67890",
]


@dataclass(frozen=True)
class PatternHit:
    name: str
    detail: str


def has_repeated_char_run(password: str, run_len: int = 4) -> bool:
    if run_len <= 1:
        return False

    count = 1
    prev = None
    for c in password:
        if c == prev:
            count += 1
            if count >= run_len:
                return True
        else:
            count = 1
            prev = c

    return False


def _is_sequence(s: str) -> bool:
    if len(s) < 4:
        return False

    diffs = [ord(s[i + 1]) - ord(s[i]) for i in range(len(s) - 1)]
    if all(d == 1 for d in diffs):
        return True
    if all(d == -1 for d in diffs):
        return True
    return False


def has_simple_sequence(password: str) -> bool:
    p = password.lower()
    for i in range(0, len(p) - 3):
        window = p[i : i + 4]
        if _is_sequence(window):
            return True
    return False


def has_keyboard_walk(password: str) -> bool:
    p = password.lower()
    for walk in _COMMON_KEYBOARD_WALKS:
        if walk in p or walk[::-1] in p:
            return True
    return False


def is_common_password(password: str, common_passwords_path: Path) -> bool:
    if not common_passwords_path.exists():
        return False

    p = password.strip().lower()
    for line in common_passwords_path.read_text(encoding="utf-8").splitlines():
        w = line.strip().lower()
        if not w or w.startswith("#"):
            continue
        if p == w:
            return True
    return False


def detect_patterns(password: str, common_passwords_path: Path) -> list[PatternHit]:
    hits: list[PatternHit] = []

    if has_repeated_char_run(password):
        hits.append(PatternHit(name="repeated_chars", detail="Contains repeated character runs"))
    if has_simple_sequence(password):
        hits.append(PatternHit(name="sequence", detail="Contains simple sequential characters"))
    if has_keyboard_walk(password):
        hits.append(PatternHit(name="keyboard_walk", detail="Contains keyboard-walk patterns"))
    if is_common_password(password, common_passwords_path):
        hits.append(PatternHit(name="common_password", detail="Matches a common password"))

    return hits
