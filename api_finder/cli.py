"""CLI interface for api-misuse-finder."""

import sys
import click
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .rules import load_rules, get_default_rules
from .scanner import scan_directory
from .output import print_report, to_json

console = Console()
err_console = Console(file=sys.stderr)


@click.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--rules", "-r", "rules_file", type=click.Path(exists=True), help="Custom rules YAML file")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("--min-severity", type=click.Choice(["warning", "error"]), default="warning", help="Minimum severity to report")
@click.option("--fail-on", type=click.Choice(["warning", "error", "none"]), default="none", help="Exit 1 if severity found")
@click.version_option()
def main(path: str, rules_file: str, output_format: str, min_severity: str, fail_on: str):
    """Detect API misuse patterns in your codebase.

    Examples:

        api-finder ./src
        api-finder --rules ./my-rules.yaml ./src
        api-finder --fail-on error ./src
    """
    project_path = Path(path).resolve()

    # Load rules
    if rules_file:
        rules = load_rules(Path(rules_file))
        err_console.print(f"[dim]Loaded {len(rules)} custom rules[/dim]")
    else:
        rules = get_default_rules()
        err_console.print(f"[dim]Using {len(rules)} built-in rules[/dim]")

    err_console.print(f"[bold blue]Scanning:[/] {project_path}")

    # Scan
    violations = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning files...", total=None)
        for v in scan_directory(project_path, rules):
            violations.append(v)

    # Filter by severity
    if min_severity == "error":
        violations = [v for v in violations if v.rule.severity == "error"]

    # Output
    if output_format == "json":
        click.echo(to_json(violations))
    else:
        print_report(violations, console)

    # Exit code
    if fail_on != "none":
        severities = {"warning": 1, "error": 2}
        threshold = severities[fail_on]
        for v in violations:
            if severities.get(v.rule.severity, 0) >= threshold:
                sys.exit(1)


if __name__ == "__main__":
    main()
