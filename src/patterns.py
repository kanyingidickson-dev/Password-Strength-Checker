from __future__ import annotations

import importlib.resources
from dataclasses import dataclass
from pathlib import Path


def _build_keyboard_adjacency() -> dict[str, set[str]]:
    rows = [
        "`1234567890-=",
        "qwertyuiop[]\\",
        "asdfghjkl;'",
        "zxcvbnm,./",
    ]

    pos: dict[str, tuple[int, int]] = {}
    for y, row in enumerate(rows):
        for x, c in enumerate(row):
            pos[c] = (x, y)

    adj: dict[str, set[str]] = {}
    for c, (x0, y0) in pos.items():
        out: set[str] = set()
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dx == 0 and dy == 0:
                    continue
                x = x0 + dx
                y = y0 + dy
                if y < 0 or y >= len(rows):
                    continue
                row = rows[y]
                if x < 0 or x >= len(row):
                    continue
                out.add(row[x])
        adj[c] = out

    return adj


_KEYBOARD_ADJ = _build_keyboard_adjacency()


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
    run = 1
    for i in range(1, len(p)):
        prev = p[i - 1]
        cur = p[i]
        neigh = _KEYBOARD_ADJ.get(prev)
        if neigh is not None and cur in neigh:
            run += 1
            if run >= 4:
                return True
        else:
            run = 1
    return False


def is_common_password(password: str, common_passwords_path: Path) -> bool:
    p = password.strip().lower()

    if common_passwords_path.exists():
        lines = common_passwords_path.read_text(encoding="utf-8").splitlines()
    else:
        try:
            lines = (
                importlib.resources.files("src.data")
                .joinpath("common_passwords.txt")
                .read_text(encoding="utf-8")
                .splitlines()
            )
        except (FileNotFoundError, ModuleNotFoundError):
            return False

    for line in lines:
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
