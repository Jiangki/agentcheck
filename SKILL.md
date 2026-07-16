# AgentCheck

> Use this skill to run the local AgentCheck CLI on an Agent Skill directory before publish.

## When to use

Before committing or releasing a Claude/Cursor Skill folder, run a read-only check for broken references, dangerous shell patterns, missing metadata, and excessive permission requests.

## How to run

```bash
git clone https://github.com/Jiangki/agentcheck.git
cd agentcheck
pip install -e .
python3 -m agentcheck check <path-to-skill-dir>
python3 -m agentcheck check <path-to-skill-dir> --json
python3 -m agentcheck check <path-to-skill-dir> --output report.md
```

Exit codes: `0` clean of errors, `1` error-level findings, `2` invalid path/ops error.

## Safety

Do not upload the skill directory to a cloud scanner. AgentCheck is local and must not execute files inside the checked directory.

## Non-goals

Not a SaaS, not auto-fix, not a general CVE scanner.
