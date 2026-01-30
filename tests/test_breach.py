from __future__ import annotations

import urllib.error
from unittest.mock import patch

from src.breach import check_pwned_password_k_anonymity


class _FakeResponse:
    def __init__(self, body: str):
        self._body = body

    def read(self) -> bytes:
        return self._body.encode("utf-8")

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_breach_returns_count_when_suffix_matches():
    body = (
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"
        "ABCDEF:1\n"
    )

    with patch("urllib.request.urlopen", return_value=_FakeResponse(body)):
        assert check_pwned_password_k_anonymity("password") == 42


def test_breach_returns_zero_when_not_found():
    body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n"

    with patch("urllib.request.urlopen", return_value=_FakeResponse(body)):
        assert check_pwned_password_k_anonymity("password") == 0


def test_breach_returns_none_on_network_error():
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
        assert check_pwned_password_k_anonymity("password") is None
