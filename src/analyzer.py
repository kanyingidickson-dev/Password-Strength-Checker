from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.breach import check_pwned_password_k_anonymity
from src.entropy import estimate_entropy_bits
from src.patterns import detect_patterns
from src.reuse import ReuseResult, check_reuse, save_to_history


@dataclass(frozen=True)
class Analysis:
    score: int
    label: str
    entropy_bits: float
    reasons: list[str]
    is_reused: bool
    breach_count: int | None


def _label(score: int) -> str:
    if score < 40:
        return "weak"
    if score < 70:
        return "ok"
    return "strong"


def analyze_password(
    password: str,
    *,
    common_passwords_path: Path,
    history_path: Path,
    history_pepper: str,
    check_breach: bool,
    save_history: bool,
) -> Analysis:
    reasons: list[str] = []

    if not password:
        return Analysis(
            score=0,
            label="weak",
            entropy_bits=0.0,
            reasons=["Password is empty"],
            is_reused=False,
            breach_count=None,
        )

    score = 0

    length = len(password)
    if length < 8:
        reasons.append("Too short (< 8 characters)")
        score -= 25
    elif length < 12:
        reasons.append("Acceptable length (8–11), but longer is better")
        score += 10
    else:
        reasons.append("Good length (>= 12)")
        score += 25

    entropy = estimate_entropy_bits(password)
    if entropy < 40:
        reasons.append(f"Low estimated entropy ({entropy:.1f} bits)")
        score -= 20
    elif entropy < 60:
        reasons.append(f"Moderate estimated entropy ({entropy:.1f} bits)")
        score += 10
    else:
        reasons.append(f"High estimated entropy ({entropy:.1f} bits)")
        score += 25

    hits = detect_patterns(password, common_passwords_path)
    for hit in hits:
        reasons.append(f"Pattern detected: {hit.detail}")

    if any(h.name == "common_password" for h in hits):
        score -= 60
    if any(h.name in {"keyboard_walk", "sequence"} for h in hits):
        score -= 20
    if any(h.name == "repeated_chars" for h in hits):
        score -= 10

    reuse: ReuseResult = check_reuse(password, history_path, history_pepper)
    if reuse.is_reused:
        reasons.append("Password appears to be reused (seen in local history)")
        score -= 30

    breach_count: int | None = None
    if check_breach:
        breach_count = check_pwned_password_k_anonymity(password)
        if breach_count is None:
            reasons.append("Breach check unavailable (network error)")
        elif breach_count > 0:
            reasons.append(f"Found in breach corpus ({breach_count} occurrences)")
            score -= 50
        else:
            reasons.append("Not found in breach corpus (k-anonymity check)")
            score += 5

    score = max(0, min(100, score + 50))

    if save_history:
        save_to_history(reuse.digest_hex, history_path)

    return Analysis(
        score=score,
        label=_label(score),
        entropy_bits=entropy,
        reasons=reasons,
        is_reused=reuse.is_reused,
        breach_count=breach_count,
    )
