"""File scanner."""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .rules import Rule, Violation, match_rule, get_language_from_file


def scan_file(file_path: Path, rules: list[Rule]) -> Iterator[Violation]:
    """Scan a file for rule violations."""
    try:
        content = file_path.read_text(errors="ignore")
    except Exception:
        return

    lines = content.split("\n")
    language = get_language_from_file(file_path)

    for rule in rules:
        # Skip rules for other languages
        if rule.language != "any" and rule.language != language:
            continue

        for i, line in enumerate(lines):
            # Get context (3 lines before and after)
            start = max(0, i - 3)
            end = min(len(lines), i + 4)
            context = lines[start:end]

            if match_rule(rule, line, context):
                yield Violation(
                    rule=rule,
                    file=str(file_path),
                    line=i + 1,
                    code=line.strip(),
                )


def scan_directory(
    path: Path,
    rules: list[Rule],
    extensions: list[str] | None = None,
) -> Iterator[Violation]:
    """Scan a directory for rule violations."""
    if extensions is None:
        extensions = [".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"]

    # Common directories to skip
    skip_dirs = {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".next",
        ".tox",
        ".eggs",
    }

    for file_path in path.rglob("*"):
        if file_path.is_dir():
            continue

        # Skip if in excluded directory
        if any(part in skip_dirs for part in file_path.parts):
            continue

        # Check extension
        if file_path.suffix.lower() not in extensions:
            continue

        yield from scan_file(file_path, rules)
