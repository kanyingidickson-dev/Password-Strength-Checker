# Password Strength Checker

A local password analysis tool that produces a clear strength score and explanations.

The goal is not “perfect security math” — it’s practical, explainable checks that map to common real‑world password failures.

## Tech stack

- Python 3 (standard library)
- pytest

## Features

- Length checks
- Entropy estimation (bits)
- Common pattern detection (repeats, sequences, keyboard walks, common passwords)
- Password reuse detection (hashed local history)
- Optional breach check using the HaveIBeenPwned Pwned Passwords k‑anonymity API

## Folder structure

- `src/` core logic
- `data/` wordlists and local history (no plaintext passwords)
- `tests/` unit tests

## How to run locally

```bash
pip install -r requirements.txt
python -m src.cli --password "CorrectHorseBatteryStaple"
```

With history tracking (recommended):

```bash
cp .env.example .env
python -m src.cli --password "CorrectHorseBatteryStaple" --save-history
```

Optional breach check (makes an external network request):

```bash
python -m src.cli --password "password123" --check-breach
```

## Output

The CLI prints:
- a numeric score (0–100)
- a label (`weak`, `ok`, `strong`)
- a list of reasons (what helped/hurt the score)

## Security decisions

- **No plaintext storage**: reuse detection stores only a SHA‑256 digest of the password combined with a user-controlled pepper.
- **Pepper is required for meaningful reuse detection**: without a pepper, hashes are vulnerable to offline guessing if the history file is exfiltrated.
- **Breach check uses k‑anonymity**: only the first 5 chars of the SHA‑1 hash are sent, never the full password.

## Design decisions

- Rules are implemented as small functions returning both a score delta and human-readable reasons.
- Entropy is treated as a *signal*, not a guarantee; pattern checks reduce the score even when entropy looks high.

## Future improvements

- Better keyboard-walk detection (full adjacency graph)
- Language-specific word detection
- Configurable policy profiles (NIST-like vs strict)
- More robust entropy models
