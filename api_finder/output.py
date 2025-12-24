"""Output formatting."""

import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .rules import Violation


def print_report(
    violations: list[Violation],
    console: Console,
    group_by_file: bool = True,
) -> None:
    """Print violations as rich report."""
    if not violations:
        console.print("[green]No API misuse patterns found![/green]")
        return

    # Count by severity
    errors = sum(1 for v in violations if v.rule.severity == "error")
    warnings = sum(1 for v in violations if v.rule.severity == "warning")

    console.print()
    console.print("[bold]API Misuse Report[/bold]")
    console.print("=" * 50)
    console.print()

    if group_by_file:
        # Group by file
        by_file: dict[str, list[Violation]] = {}
        for v in violations:
            by_file.setdefault(v.file, []).append(v)

        for file, file_violations in sorted(by_file.items()):
            console.print(f"[bold cyan]{file}[/bold cyan]")
            for v in sorted(file_violations, key=lambda x: x.line):
                icon = "[red]" if v.rule.severity == "error" else "[yellow]⚠️[/yellow]"
                console.print(f"  {v.line}: {icon} {v.rule.id}")
                console.print(f"       [dim]{v.code}[/dim]")
                console.print(f"       {v.rule.message}")
                if v.rule.suggestion:
                    console.print(f"       [green]→ {v.rule.suggestion}[/green]")
                console.print()
    else:
        for v in violations:
            icon = "[red]" if v.rule.severity == "error" else "[yellow]⚠️[/yellow]"
            console.print(f"{v.file}:{v.line}")
            console.print(f"  {icon} {v.rule.id}")
            console.print(f"  {v.rule.message}")
            if v.rule.suggestion:
                console.print(f"  [green]→ {v.rule.suggestion}[/green]")
            console.print()

    # Summary
    console.print("=" * 50)
    summary_parts = []
    if errors:
        summary_parts.append(f"[red]{errors} error(s)[/red]")
    if warnings:
        summary_parts.append(f"[yellow]{warnings} warning(s)[/yellow]")
    console.print("Summary: " + ", ".join(summary_parts))


def to_json(violations: list[Violation]) -> str:
    """Convert violations to JSON."""
    data = []
    for v in violations:
        data.append(
            {
                "file": v.file,
                "line": v.line,
                "code": v.code,
                "rule_id": v.rule.id,
                "message": v.rule.message,
                "severity": v.rule.severity,
                "suggestion": v.rule.suggestion,
            }
        )
    return json.dumps(data, indent=2)
