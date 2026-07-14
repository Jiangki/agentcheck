"""Command-line interface for AgentCheck."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .report import render_json, render_markdown, render_text, write_report
from .rules import run_rules
from .scanner import ScanError, scan_directory


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentcheck",
        description="Read-only pre-publish checks for Agent Skill directories.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="check one Skill directory")
    check.add_argument("skill_dir", type=Path, help="path to the Skill directory")
    check.add_argument(
        "--json",
        action="store_true",
        help="print JSON instead of the human-readable terminal report",
    )
    check.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write Markdown (or JSON with --json) to this file",
    )
    return parser


def _check(args: argparse.Namespace) -> int:
    try:
        scan = scan_directory(args.skill_dir)
    except ScanError as exc:
        print("agentcheck: error: {}".format(exc), file=sys.stderr)
        return EXIT_USAGE

    findings = run_rules(scan)
    terminal_report = (
        render_json(scan, findings) if args.json else render_text(scan, findings)
    )

    if args.output is not None:
        file_report = (
            render_json(scan, findings)
            if args.json
            else render_markdown(scan, findings)
        )
        try:
            write_report(args.output.expanduser(), file_report)
        except OSError as exc:
            print(
                "agentcheck: error: cannot write report '{}': {}".format(
                    args.output, exc
                ),
                file=sys.stderr,
            )
            return EXIT_USAGE

    print(terminal_report)
    if any(finding.severity == "error" for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return _check(args)
    parser.error("a command is required")
    return EXIT_USAGE
