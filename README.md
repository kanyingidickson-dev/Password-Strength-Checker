# Password Strength Checker

![CI](https://github.com/kanyingidickson-dev/Password-Strength-Checker/actions/workflows/ci.yml/badge.svg)

A local password analysis tool that produces a clear strength score and explanations.

The goal is not “perfect security math” but practical, explainable checks that map to common real‑world password failures.

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
- `docs/` static web app (GitHub Pages)
- `web_tests/` frontend unit tests

## How to run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python3 -m src.cli --password "CorrectHorseBatteryStaple"
```

Interactive (recommended to avoid shell history):

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python3 -m src.cli
```

With history tracking (recommended):

```bash
cp .env.example .env
python3 -m src.cli --password "CorrectHorseBatteryStaple" --save-history
```

Optional breach check (makes an external network request):

```bash
python3 -m src.cli --password "password123" --check-breach
```

## Development

Run tests:

```bash
python -m pytest
```

Lint:

```bash
python -m ruff check .
```

Type-check:

```bash
python -m mypy src
```

Web tests:

```bash
node --test web_tests
```

## Web app (GitHub Pages)

This repo includes a static web app under `docs/`.

It includes:

- Password strength analysis (explainable scoring)
- Strong password generator
- Offline crypto utilities (hash/HMAC with optional verification, PBKDF2, AES-GCM, Base64)

Enable GitHub Pages:

- **Source**: `Deploy from a branch`
- **Branch**: `main`
- **Folder**: `/docs`

Local preview:

```bash
python3 -m http.server 8000 --directory docs
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
- Configurable scoring weights and rule toggles
- Optional JSON output for automation and CI usage
- Packaging polish (installable CLI entry point)
- Expanded test suite (property-based tests, fuzzing)
