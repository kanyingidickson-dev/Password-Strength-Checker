from __future__ import annotations

import hashlib
import urllib.request


def _sha1_hex(password: str) -> str:
    h = hashlib.sha1()  # noqa: S324
    h.update(password.encode("utf-8"))
    return h.hexdigest().upper()


def check_pwned_password_k_anonymity(password: str, timeout_seconds: int = 10) -> int:
    sha1 = _sha1_hex(password)
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "password-checker"})

    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        body = resp.read().decode("utf-8")

    for line in body.splitlines():
        if ":" not in line:
            continue
        sfx, count = line.split(":", 1)
        if sfx.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0

    return 0
