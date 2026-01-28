from pathlib import Path

from src.reuse import check_reuse, save_to_history


def test_reuse_round_trip(tmp_path: Path):
    history = tmp_path / "history.json"
    pepper = "pepper"

    r1 = check_reuse("secret", history, pepper)
    assert r1.is_reused is False

    save_to_history(r1.digest_hex, history)

    r2 = check_reuse("secret", history, pepper)
    assert r2.is_reused is True
