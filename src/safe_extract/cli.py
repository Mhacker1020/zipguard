"""CLI entry point for safe-extract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from safe_extract.audit import Decision
from safe_extract.extractor import SafeExtractor
from safe_extract.policy import ExtractionPolicy

console = Console()
err_console = Console(stderr=True)

_DECISION_STYLE = {
    Decision.ALLOWED: "green",
    Decision.RENAMED: "yellow",
    Decision.BLOCKED: "red",
    Decision.SKIPPED: "dim",
}


def build_policy(args: argparse.Namespace) -> ExtractionPolicy:
    if args.config:
        policy = ExtractionPolicy.from_file(Path(args.config))
    else:
        policy = ExtractionPolicy()

    if args.max_size:
        policy.max_file_size = _parse_size(args.max_size)
    if args.block_ext:
        extras = [e.strip() if e.startswith(".") else f".{e.strip()}"
                  for e in args.block_ext.split(",")]
        policy.block_extensions = list(set(policy.block_extensions + extras))

    return policy


def _parse_size(value: str) -> int:
    """Parse human-readable size like '100MB', '500KB', '1GB'."""
    value = value.strip().upper()
    units = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    for unit, multiplier in units.items():
        if value.endswith(unit):
            return int(value[:-len(unit)]) * multiplier
    return int(value)  # assume bytes


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="safe-extract",
        description="Security-focused archive extraction with policy enforcement",
    )
    parser.add_argument("--version", action="version", version="safe-extract 0.1.0")
    parser.add_argument("archive", help="Archive file to extract (ZIP supported)")
    parser.add_argument("--out", "-o", default="./extracted", help="Output directory (default: ./extracted)")
    parser.add_argument("--dry-run", action="store_true", help="Analyze without extracting")
    parser.add_argument("--config", "-c", help="Policy config file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all entries including allowed")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--log", help="Save JSON audit log to file")
    parser.add_argument("--max-size", help="Max file size (e.g. 100MB)")
    parser.add_argument("--block-ext", help="Comma-separated extensions to block (e.g. .exe,.ps1)")

    args = parser.parse_args()

    archive = Path(args.archive)
    if not archive.exists():
        err_console.print(f"[red]Error:[/red] Archive not found: {archive}")
        sys.exit(1)

    policy = build_policy(args)
    extractor = SafeExtractor(policy)

    if args.dry_run:
        console.print(f"[dim]Dry run — analyzing[/dim] [bold]{archive.name}[/bold]")
    else:
        console.print(f"[dim]Extracting[/dim] [bold]{archive.name}[/bold] [dim]→[/dim] {args.out}")

    report = extractor.extract(archive, Path(args.out), dry_run=args.dry_run)

    if report.aborted:
        err_console.print(f"\n[bold red]ABORTED:[/bold red] {report.abort_reason}")
        sys.exit(2)

    if args.format == "json":
        console.print(report.to_json())
    else:
        _print_table(report, verbose=args.verbose)

    if args.log:
        report.save(Path(args.log))
        console.print(f"\n[dim]Audit log saved to {args.log}[/dim]")

    blocked = report.blocked_count
    sys.exit(1 if blocked > 0 and not args.dry_run else 0)


def _print_table(report, verbose: bool) -> None:
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Decision", width=9)
    table.add_column("File")
    table.add_column("Reason", style="dim")

    for entry in report.entries:
        if not verbose and entry.decision in (Decision.ALLOWED, Decision.SKIPPED):
            continue
        style = _DECISION_STYLE.get(entry.decision, "")
        table.add_row(
            f"[{style}]{entry.decision.value.upper()}[/{style}]",
            entry.name,
            entry.reason,
        )

    if table.row_count > 0 or verbose:
        console.print(table)

    # Summary line
    s = report.to_dict()["summary"]
    parts = [f"[green]{s['allowed']} allowed[/green]"]
    if s["renamed"]:
        parts.append(f"[yellow]{s['renamed']} renamed[/yellow]")
    if s["blocked"]:
        parts.append(f"[red]{s['blocked']} blocked[/red]")

    console.print("  " + "  ".join(parts))

    if report.blocked_count == 0 and not verbose:
        console.print(f"  [dim]All {s['total']} entries passed — use --verbose to see details[/dim]")
