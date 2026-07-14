"""Read-only filesystem collection for AgentCheck.

This module only opens files for reading. It never imports, invokes, or shells
out to anything found in the directory being checked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


IGNORED_DIRECTORIES = frozenset({".git", ".hg", ".svn", "__pycache__"})


class ScanError(Exception):
    """Raised when a directory cannot be scanned safely."""


@dataclass(frozen=True)
class ScannedFile:
    """Metadata and optional UTF-8-compatible text for one regular file."""

    path: str
    size: int
    text: Optional[str]


@dataclass(frozen=True)
class ScanResult:
    """The immutable input consumed by the rule engine."""

    root: Path
    files: Tuple[ScannedFile, ...]
    symlinks: Tuple[str, ...]

    @property
    def scanned_files(self) -> int:
        return len(self.files)


def _read_text(path: Path) -> Optional[str]:
    """Return decoded text, or None for files that appear to be binary."""

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ScanError("cannot read '{}': {}".format(path, exc)) from exc

    if b"\x00" in data[:8192]:
        return None

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Replacement decoding keeps checks deterministic for mostly-text files
        # without treating arbitrary binary data as executable or structured.
        return data.decode("utf-8", errors="replace")


def scan_directory(path: Path) -> ScanResult:
    """Collect regular files beneath *path* without following symbolic links."""

    try:
        root = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScanError("path does not exist or cannot be resolved: {}".format(path)) from exc

    if not root.is_dir():
        raise ScanError("path is not a directory: {}".format(path))

    files = []
    symlinks = []

    def on_walk_error(exc: OSError) -> None:
        raise ScanError("cannot scan '{}': {}".format(exc.filename or root, exc))

    try:
        for current, directory_names, file_names in os.walk(
            str(root), topdown=True, followlinks=False, onerror=on_walk_error
        ):
            directory_names.sort()
            file_names.sort()
            current_path = Path(current)

            retained_directories = []
            for name in directory_names:
                child = current_path / name
                relative = child.relative_to(root).as_posix()
                if child.is_symlink():
                    symlinks.append(relative)
                elif name not in IGNORED_DIRECTORIES:
                    retained_directories.append(name)
            directory_names[:] = retained_directories

            for name in file_names:
                child = current_path / name
                relative = child.relative_to(root).as_posix()
                if child.is_symlink():
                    symlinks.append(relative)
                    continue
                if not child.is_file():
                    continue
                try:
                    size = child.stat().st_size
                except OSError as exc:
                    raise ScanError("cannot inspect '{}': {}".format(child, exc)) from exc
                files.append(ScannedFile(relative, size, _read_text(child)))
    except ScanError:
        raise
    except OSError as exc:
        raise ScanError("cannot scan '{}': {}".format(root, exc)) from exc

    return ScanResult(
        root=root,
        files=tuple(sorted(files, key=lambda item: item.path)),
        symlinks=tuple(sorted(symlinks)),
    )
