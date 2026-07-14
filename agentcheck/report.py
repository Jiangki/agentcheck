"""Human-readable, Markdown, and JSON report rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .rules import Finding
from .scanner import ScanResult


def _summary(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {"errors": 0, "warnings": 0}
    for finding in findings:
        if finding.severity == "error":
            counts["errors"] += 1
        elif finding.severity == "warning":
            counts["warnings"] += 1
    return counts


def _finding_dict(finding: Finding) -> Dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "path": finding.path,
        "line": finding.line,
        "message": finding.message,
        "hint": finding.hint,
    }


def report_data(scan: ScanResult, findings: List[Finding]) -> Dict[str, Any]:
    return {
        "tool": "agentcheck",
        "version": "0.1.0",
        "root": str(scan.root),
        "scanned_files": scan.scanned_files,
        "summary": _summary(findings),
        "findings": [_finding_dict(finding) for finding in findings],
    }


def render_json(scan: ScanResult, findings: List[Finding]) -> str:
    return json.dumps(
        report_data(scan, findings), ensure_ascii=False, indent=2, sort_keys=True
    )


def _location(finding: Finding) -> str:
    if finding.line is None:
        return finding.path
    return "{}:{}".format(finding.path, finding.line)


def render_text(scan: ScanResult, findings: List[Finding]) -> str:
    counts = _summary(findings)
    lines = [
        "AgentCheck scanned {} files in {}".format(scan.scanned_files, scan.root),
        "Found {} errors and {} warnings.".format(
            counts["errors"], counts["warnings"]
        ),
    ]
    if not findings:
        lines.append("No issues found.")
    else:
        lines.append("")
        for finding in findings:
            lines.append(
                "{} [{}] {} {}".format(
                    _location(finding),
                    finding.severity.upper(),
                    finding.rule_id,
                    finding.message,
                )
            )
            lines.append("  Hint: {}".format(finding.hint))
    return "\n".join(lines)


def render_markdown(scan: ScanResult, findings: List[Finding]) -> str:
    counts = _summary(findings)
    lines = [
        "# AgentCheck report",
        "",
        "- Root: `{}`".format(scan.root),
        "- Scanned files: {}".format(scan.scanned_files),
        "- Errors: {}".format(counts["errors"]),
        "- Warnings: {}".format(counts["warnings"]),
        "",
    ]
    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule | Location | Message |",
            "|---|---|---|---|",
        ]
    )
    for finding in findings:
        message = finding.message.replace("|", "\\|")
        lines.append(
            "| {} | `{}` | `{}` | {} |".format(
                finding.severity,
                finding.rule_id,
                _location(finding),
                message,
            )
        )
    lines.extend(["", "## Remediation hints", ""])
    for finding in findings:
        lines.append(
            "- **{}** at `{}`: {}".format(
                finding.rule_id, _location(finding), finding.hint
            )
        )
    return "\n".join(lines)


def write_report(path: Path, content: str) -> None:
    path.write_text(content + "\n", encoding="utf-8")
