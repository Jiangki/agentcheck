"""Deterministic, offline rules for AgentCheck."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlsplit

from .scanner import ScanResult, ScannedFile


MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 256 * 1024


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: Optional[int]
    message: str
    hint: str

    def sort_key(self) -> Tuple[int, str, int, str]:
        severity_rank = {"error": 0, "warning": 1}
        return (
            severity_rank.get(self.severity, 2),
            self.path,
            self.line or 0,
            self.rule_id,
        )


Rule = Callable[[ScanResult], Iterable[Finding]]


MARKDOWN_LINK_RE = re.compile(
    r"!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^)\s]+))"
)
H1_RE = re.compile(r"(?m)^#\s+\S")
DESCRIPTION_RE = re.compile(
    r"(?im)^(?:description\s*:|\*\*description\*\*\s*:)\s*\S"
)
LICENSE_RE = re.compile(r"(?im)^(?:license\s*:|##\s+licen[cs]e\b)")
ENV_REFERENCE_RE = re.compile(
    r"(?<!\\)(?:\$\{([A-Z][A-Z0-9_]*)[^}]*\}|\$([A-Z][A-Z0-9_]*))"
)
ENV_ASSIGNMENT_RE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=")
SAFE_ENVIRONMENT_VARIABLES = frozenset(
    {
        "HOME",
        "PATH",
        "PWD",
        "OLDPWD",
        "SHELL",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "TERM",
        "CI",
    }
)

DANGEROUS_SHELL_PATTERNS: Sequence[Tuple[re.Pattern[str], str]] = (
    (
        re.compile(
            r"(?im)^\s*(?:sudo\s+)?rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/(?:\*|\s|$)"
        ),
        "recursive forced deletion targets the filesystem root",
    ),
    (
        re.compile(
            r"(?i)\b(?:curl|wget)\b[^\n|]{0,500}\|\s*"
            r"(?:sudo\s+)?(?:sh|bash|zsh)\b"
        ),
        "downloaded content is piped directly to a shell",
    ),
    (
        re.compile(r"(?im)^\s*(?:sudo\s+)?chmod\s+(?:-R\s+)?777\s+/(?:\s|$)"),
        "world-writable permissions are applied at the filesystem root",
    ),
)

SENSITIVE_PERMISSION_RE = re.compile(
    r"(?i)\b(?:read|access|copy|upload|send|collect)\b[^\n]{0,100}"
    r"(?:~/\.ssh(?:/|\b)|~/\.aws/credentials\b|/etc/shadow\b)"
)
ELEVATED_PERMISSION_RE = re.compile(
    r"(?i)\b(?:run|execute|open|start|requires?|use)\b[^\n]{0,40}"
    r"(?:as\s+root\b|with\s+sudo\b|sudo\s+-[is]\b)"
)


def _text_files(scan: ScanResult) -> Iterable[ScannedFile]:
    return (item for item in scan.files if item.text is not None)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _markdown_links(text: str) -> Iterable[Tuple[str, int]]:
    for match in MARKDOWN_LINK_RE.finditer(text):
        target = (match.group(1) or match.group(2) or "").strip()
        if target:
            yield target, _line_number(text, match.start())


def _manifest(scan: ScanResult) -> Optional[ScannedFile]:
    by_path = {item.path: item for item in scan.files}
    return by_path.get("SKILL.md") or by_path.get("README.md")


def check_meta_title(scan: ScanResult) -> Iterable[Finding]:
    manifest = _manifest(scan)
    if manifest is None:
        yield Finding(
            "META001",
            "error",
            "SKILL.md",
            None,
            "root SKILL.md or README.md is missing",
            "Add SKILL.md (preferred) or README.md with a level-one title.",
        )
    elif manifest.text is None or not H1_RE.search(manifest.text):
        yield Finding(
            "META001",
            "error",
            manifest.path,
            1,
            "manifest does not contain a level-one Markdown title",
            "Add a '# Skill name' heading.",
        )


def check_meta_description_license(scan: ScanResult) -> Iterable[Finding]:
    manifest = _manifest(scan)
    if manifest is None:
        return

    text = manifest.text or ""
    missing = []
    if not DESCRIPTION_RE.search(text):
        missing.append("description")

    paths = {item.path.lower() for item in scan.files}
    has_license_file = any(
        name in paths for name in ("license", "license.md", "license.txt", "copying")
    )
    if not has_license_file and not LICENSE_RE.search(text):
        missing.append("license declaration")

    if missing:
        yield Finding(
            "META002",
            "warning",
            manifest.path,
            1,
            "manifest is missing {}".format(" and ".join(missing)),
            "Declare a description and license in front matter or add a LICENSE file.",
        )


def _is_external_or_special_link(target: str) -> bool:
    lowered = target.lower()
    if lowered.startswith(("#", "/", "//", "mailto:", "data:", "tel:")):
        return True
    return bool(urlsplit(target).scheme)


def check_relative_references(scan: ScanResult) -> Iterable[Finding]:
    for item in _text_files(scan):
        if not item.path.lower().endswith((".md", ".markdown")):
            continue
        assert item.text is not None
        for target, line in _markdown_links(item.text):
            if _is_external_or_special_link(target):
                continue
            link_path = unquote(target.split("#", 1)[0].split("?", 1)[0])
            if not link_path:
                continue
            source_parent = (scan.root / item.path).parent
            try:
                candidate = (source_parent / link_path).resolve(strict=False)
                candidate.relative_to(scan.root)
            except (OSError, RuntimeError, ValueError):
                yield Finding(
                    "REF001",
                    "error",
                    item.path,
                    line,
                    "relative reference leaves the skill directory: {}".format(target),
                    "Point the link at a file inside the skill directory.",
                )
                continue
            if not candidate.exists():
                yield Finding(
                    "REF001",
                    "error",
                    item.path,
                    line,
                    "relative reference does not exist: {}".format(target),
                    "Create the target or correct the relative path.",
                )


def check_http_url_format(scan: ScanResult) -> Iterable[Finding]:
    intended_prefixes = ("http:", "https:", "http//", "https//")
    for item in _text_files(scan):
        if not item.path.lower().endswith((".md", ".markdown")):
            continue
        assert item.text is not None
        for target, line in _markdown_links(item.text):
            lowered = target.lower()
            if not lowered.startswith(intended_prefixes):
                continue
            parsed = urlsplit(target)
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or any(character.isspace() for character in target)
            ):
                yield Finding(
                    "REF002",
                    "warning",
                    item.path,
                    line,
                    "HTTP(S) link is malformed: {}".format(target),
                    "Use a complete URL such as https://example.com/path.",
                )


def check_dangerous_shell(scan: ScanResult) -> Iterable[Finding]:
    for item in _text_files(scan):
        assert item.text is not None
        seen_lines = set()
        for pattern, reason in DANGEROUS_SHELL_PATTERNS:
            for match in pattern.finditer(item.text):
                line = _line_number(item.text, match.start())
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                yield Finding(
                    "SHELL001",
                    "error",
                    item.path,
                    line,
                    reason,
                    "Replace it with a pinned, inspectable, narrowly scoped command.",
                )


def _declared_environment_variables(scan: ScanResult) -> set[str]:
    declared = set(SAFE_ENVIRONMENT_VARIABLES)
    declaration_names = {
        ".env.example",
        ".env.sample",
        "env.example",
        "env.sample",
    }
    for item in _text_files(scan):
        if Path(item.path).name.lower() not in declaration_names:
            continue
        assert item.text is not None
        declared.update(ENV_ASSIGNMENT_RE.findall(item.text))
    return declared


def check_undeclared_environment_variables(scan: ScanResult) -> Iterable[Finding]:
    declared = _declared_environment_variables(scan)
    reported = set()
    declaration_names = {
        ".env.example",
        ".env.sample",
        "env.example",
        "env.sample",
    }
    for item in _text_files(scan):
        if Path(item.path).name.lower() in declaration_names:
            continue
        assert item.text is not None
        for match in ENV_REFERENCE_RE.finditer(item.text):
            variable = match.group(1) or match.group(2)
            if variable in declared or variable in reported:
                continue
            reported.add(variable)
            yield Finding(
                "SHELL002",
                "warning",
                item.path,
                _line_number(item.text, match.start()),
                "environment variable is used but not declared: {}".format(variable),
                "Add it to .env.example (without a secret value).",
            )


def check_context_size(scan: ScanResult) -> Iterable[Finding]:
    total = sum(item.size for item in scan.files)
    for item in scan.files:
        if item.size > MAX_FILE_BYTES:
            yield Finding(
                "SIZE001",
                "warning",
                item.path,
                None,
                "file is {} bytes (limit: {})".format(item.size, MAX_FILE_BYTES),
                "Split, remove, or exclude content that the skill does not need.",
            )
    if total > MAX_TOTAL_BYTES:
        yield Finding(
            "SIZE001",
            "warning",
            ".",
            None,
            "total context is {} bytes (limit: {})".format(total, MAX_TOTAL_BYTES),
            "Keep only files required to operate the skill.",
        )


def check_excessive_permissions(scan: ScanResult) -> Iterable[Finding]:
    for item in _text_files(scan):
        assert item.text is not None
        matches = list(SENSITIVE_PERMISSION_RE.finditer(item.text))
        matches.extend(ELEVATED_PERMISSION_RE.finditer(item.text))
        seen_lines = set()
        for match in sorted(matches, key=lambda value: value.start()):
            line = _line_number(item.text, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            yield Finding(
                "PERM001",
                "error",
                item.path,
                line,
                "instruction requests obviously excessive local permissions",
                "Remove the request or document a narrowly scoped, opt-in alternative.",
            )


def check_symlinks(scan: ScanResult) -> Iterable[Finding]:
    for path in scan.symlinks:
        yield Finding(
            "PATH001",
            "warning",
            path,
            None,
            "symbolic link was skipped",
            "Replace the link with an in-tree regular file if it must be checked.",
        )


RULES: Sequence[Rule] = (
    check_meta_title,
    check_meta_description_license,
    check_relative_references,
    check_http_url_format,
    check_dangerous_shell,
    check_undeclared_environment_variables,
    check_context_size,
    check_excessive_permissions,
    check_symlinks,
)


def run_rules(scan: ScanResult) -> List[Finding]:
    findings = [finding for rule in RULES for finding in rule(scan)]
    return sorted(findings, key=Finding.sort_key)
