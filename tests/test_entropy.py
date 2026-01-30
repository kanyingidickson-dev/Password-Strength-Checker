from src.entropy import estimate_entropy_bits, estimate_shannon_entropy_bits


def test_entropy_empty():
    assert estimate_entropy_bits("") == 0.0
    assert estimate_shannon_entropy_bits("") == 0.0


def test_entropy_increases_with_length():
    assert estimate_entropy_bits("a") < estimate_entropy_bits("aaaa")


def test_shannon_entropy_signal():
    assert estimate_shannon_entropy_bits("aaaa") == 0.0
    assert estimate_shannon_entropy_bits("abcd") > 0.0
