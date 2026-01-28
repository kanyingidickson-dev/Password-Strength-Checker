from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReuseResult:
    is_reused: bool
    digest_hex: str


def _digest_password(password: str, pepper: str) -> str:
    h = hashlib.sha256()
    h.update(pepper.encode("utf-8"))
    h.update(b"\x00")
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def _load_history(path: Path) -> set[str]:
    if not path.exists():
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()

    items = data.get("digests") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return set()

    out: set[str] = set()
    for x in items:
        if isinstance(x, str) and len(x) == 64:
            out.add(x)
    return out


def _save_history(path: Path, digests: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"digests": sorted(digests)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_reuse(password: str, history_path: Path, pepper: str) -> ReuseResult:
    digest = _digest_password(password, pepper)
    digests = _load_history(history_path)
    return ReuseResult(is_reused=digest in digests, digest_hex=digest)


def save_to_history(digest_hex: str, history_path: Path) -> None:
    digests = _load_history(history_path)
    digests.add(digest_hex)
    _save_history(history_path, digests)
