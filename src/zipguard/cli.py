"""CLI entry point for zipguard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from zipguard.audit import Decision
from zipguard.extractor import SafeExtractor
from zipguard.policy import ExtractionPolicy

# ANSI color codes
_R = "\033[0m"       # reset
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"

_DECISION_COLOR = {
    Decision.ALLOWED: _GREEN,
    Decision.RENAMED: _YELLOW,
    Decision.BLOCKED: _RED,
    Decision.SKIPPED: _DIM,
}


def _c(color: str, text: str) -> str:
    return f"{color}{text}{_R}"


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


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
        prog="zipguard",
        description="Security-focused archive extraction with policy enforcement",
    )
    parser.add_argument("--version", action="version", version="zipguard 0.2.0")
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
        _err(f"{_c(_RED, 'Error:')} Archive not found: {archive}")
        sys.exit(1)

    policy = build_policy(args)
    extractor = SafeExtractor(policy)

    if args.dry_run:
        print(f"{_c(_DIM, 'Dry run — analyzing')} {_c(_BOLD, archive.name)}")
    else:
        print(f"{_c(_DIM, 'Extracting')} {_c(_BOLD, archive.name)} {_c(_DIM, '→')} {args.out}")

    report = extractor.extract(archive, Path(args.out), dry_run=args.dry_run)

    if report.aborted:
        _err(f"\n{_c(_RED, _c(_BOLD, 'ABORTED:'))} {report.abort_reason}")
        sys.exit(2)

    if args.format == "json":
        print(report.to_json())
    else:
        _print_table(report, verbose=args.verbose)

    if args.log:
        report.save(Path(args.log))
        print(f"\n{_c(_DIM, f'Audit log saved to {args.log}')}")

    sys.exit(1 if report.blocked_count > 0 and not args.dry_run else 0)


def _print_table(report, verbose: bool) -> None:
    COL_DECISION = 11
    COL_FILE = 40

    rows = [
        entry for entry in report.entries
        if verbose or entry.decision not in (Decision.ALLOWED, Decision.SKIPPED)
    ]

    if rows or verbose:
        header = (
            f"  {'Decision':<{COL_DECISION}}{'File':<{COL_FILE}}Reason"
        )
        print(f"\n{_c(_BOLD, header)}")
        print(" " + "─" * (COL_DECISION + COL_FILE + 40))
        for entry in rows:
            color = _DECISION_COLOR.get(entry.decision, "")
            decision = _c(color, f"{entry.decision.value.upper():<{COL_DECISION}}")
            filename = f"{entry.name:<{COL_FILE}}"
            reason = _c(_DIM, entry.reason) if entry.reason else ""
            print(f"  {decision}{filename}{reason}")
        print()

    # Summary line
    s = report.to_dict()["summary"]
    parts = [_c(_GREEN, f"{s['allowed']} allowed")]
    if s["renamed"]:
        parts.append(_c(_YELLOW, f"{s['renamed']} renamed"))
    if s["blocked"]:
        parts.append(_c(_RED, f"{s['blocked']} blocked"))

    print("  " + "  ".join(parts))

    if report.blocked_count == 0 and not verbose:
        total = s['total']
        print(f"  {_c(_DIM, f'All {total} entries passed — use --verbose to see details')}")
