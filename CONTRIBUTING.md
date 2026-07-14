# Contributing to AgentCheck

## Principles

- Keep checks **deterministic** and **offline**.
- Never execute code from the directory under scan.
- Prefer standard library; justify any new dependency.
- Every rule needs a stable `RULE_ID`, severity, message, and hint.
- Add or update fixtures when you change rule behavior.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python3 tests/test_agentcheck.py
```

## Pull requests

1. Describe the user-facing change.
2. Include fixture coverage for new findings.
3. Keep the README rule table in sync.
