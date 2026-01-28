from src.entropy import estimate_entropy_bits


def test_entropy_empty():
    assert estimate_entropy_bits("") == 0.0


def test_entropy_increases_with_length():
    assert estimate_entropy_bits("a") < estimate_entropy_bits("aaaa")
