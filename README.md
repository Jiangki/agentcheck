# AgentCheck

Read-only pre-publish checker for **Claude / Cursor Agent Skill** directories.

Think of it as a small, deterministic **ESLint for Skills**: it scans a skill folder locally, reports stable rule IDs with file paths, and exits non-zero when error-level issues are found. It never uploads your files and never executes code inside the checked directory.

> Status: open-source MVP for validation. Not a SaaS. Not a paid-demand claim.

## Requirements

- Python 3.9+
- No third-party runtime dependencies

## Quick start

```bash
git clone https://github.com/Jiangki/agentcheck.git
cd agentcheck

# Demo fixtures
python3 -m agentcheck check fixtures/good-skill   # exit 0
python3 -m agentcheck check fixtures/bad-skill    # exit 1

# Check your own skill
python3 -m agentcheck check /path/to/your-skill
python3 -m agentcheck check /path/to/your-skill --json
python3 -m agentcheck check /path/to/your-skill --output report.md
```

Optional install as a console script:

```bash
pip install -e .
agentcheck check /path/to/your-skill
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No error-level findings (warnings allowed) |
| `1` | One or more error-level findings |
| `2` | Invalid path / operational error |

## Rules

| ID | Severity | Check |
|----|----------|-------|
| `META001` | error | Root `SKILL.md`/`README.md` and a level-one title exist |
| `META002` | warning | Description + license declared (or root license file) |
| `REF001` | error | Relative Markdown links resolve inside the skill tree |
| `REF002` | warning | HTTP(S) Markdown links have valid scheme + hostname (format only) |
| `SHELL001` | error | Dangerous shell forms (`rm -rf /`, `curl\|sh`, root `chmod 777`, …) |
| `SHELL002` | warning | `$ENV` used but not declared in `.env.example` |
| `SIZE001` | warning | File / total context size limits |
| `PERM001` | error | Instructions request excessive local permissions |
| `PATH001` | warning | Symlinks skipped (not followed) |

## Safety boundary

AgentCheck only lists directories, reads regular files, and inspects metadata. It does **not**:

- import or execute files from the checked directory
- run shell commands from the skill
- follow symlinks into/out of the tree for content checks
- make network requests
- write into the checked directory

## CI example

See [`action-example.yml`](action-example.yml). Copy and point it at your skill path after checking out this tool (or install from your fork).

## Agent skill wrapper

[`SKILL.md`](SKILL.md) teaches coding agents how to invoke AgentCheck before publishing a skill.

## Development

```bash
python3 tests/test_agentcheck.py
# or
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
