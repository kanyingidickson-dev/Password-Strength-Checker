from __future__ import annotations

import math
import string


def estimate_charset_size(password: str) -> int:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    has_other = any(
        (not c.islower())
        and (not c.isupper())
        and (not c.isdigit())
        and (c not in string.punctuation)
        for c in password
    )

    size = 0
    if has_lower:
        size += 26
    if has_upper:
        size += 26
    if has_digit:
        size += 10
    if has_symbol:
        size += len(string.punctuation)
    if has_other:
        size += 32

    return max(size, 1)


def estimate_entropy_bits(password: str) -> float:
    if not password:
        return 0.0

    charset = estimate_charset_size(password)
    return len(password) * math.log2(charset)


def estimate_shannon_entropy_bits(password: str) -> float:
    if not password:
        return 0.0

    counts: dict[str, int] = {}
    for c in password:
        counts[c] = counts.get(c, 0) + 1

    n = len(password)
    h = 0.0
    for count in counts.values():
        p = count / n
        h -= p * math.log2(p)

    return h * n
