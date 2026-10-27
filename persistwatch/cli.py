"""Command line entry point."""

import argparse
import sys
from typing import List, Optional, Sequence

from . import __version__
from .model import severity_rank
from .report import TECHNIQUE_NAMES, json_text, text_report
from .rules import RULES
from .scanner import filter_by_severity, scan

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="persistwatch",
        description=(
            "Scan a directory of systemd unit and timer files for signs of "
            "persistence."
        ),
        epilog=(
            "Exit codes: 0 nothing found, 1 findings at or above --min-severity, "
            "2 an error."
        ),
    )
    parser.add_argument(
        "directories",
        nargs="*",
        metavar="DIR",
        help="directory to scan, for example /etc/systemd/system",
    )
    parser.add_argument("--json", action="store_true", help="print JSON instead of a report")
    parser.add_argument(
        "--recent-days",
        type=int,
        default=7,
        metavar="N",
        help="flag units modified in the last N days (default 7, 0 disables)",
    )
    parser.add_argument(
        "--timer-threshold",
        type=int,
        default=120,
        metavar="SECONDS",
        help="flag timers that fire more often than this (default 120)",
    )
    parser.add_argument(
        "--min-severity",
        choices=("low", "medium", "high"),
        default="low",
        help="hide findings below this severity (default low)",
    )
    parser.add_argument(
        "--disable",
        action="append",
        default=[],
        metavar="RULE",
        help="turn off one rule, repeatable",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="do not walk into subdirectories",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="always exit 0, even when there are findings",
    )
    parser.add_argument("--list-rules", action="store_true", help="list the rules and exit")
    parser.add_argument("--version", action="version", version="persistwatch %s" % __version__)
    return parser


def list_rules(stream) -> int:
    stream.write("persistwatch rules\n")
    for name in sorted(RULES):
        stream.write("  %s\n" % name)
    stream.write("\nMITRE ATT&CK techniques covered\n")
    for technique in sorted(TECHNIQUE_NAMES):
        stream.write("  %-12s %s\n" % (technique, TECHNIQUE_NAMES[technique]))
    return EXIT_CLEAN


def main(argv: Optional[Sequence[str]] = None, stdout=None, stderr=None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    out = stdout or sys.stdout
    err = stderr or sys.stderr

    if args.list_rules:
        return list_rules(out)

    if not args.directories:
        parser.print_usage(err)
        err.write("persistwatch: give at least one directory to scan, or --list-rules\n")
        return EXIT_ERROR

    options = {
        "recent_days": args.recent_days,
        "timer_threshold_seconds": args.timer_threshold,
    }

    try:
        units, findings = scan(
            args.directories,
            options=options,
            disabled=args.disable,
            recursive=not args.no_recursive,
        )
    except (NotADirectoryError, OSError) as exc:
        err.write("persistwatch: %s\n" % exc)
        return EXIT_ERROR
    except ValueError as exc:
        err.write("persistwatch: %s\n" % exc)
        return EXIT_ERROR

    shown = filter_by_severity(findings, args.min_severity)

    if args.json:
        out.write(json_text(units, shown, args.directories, args.min_severity) + "\n")
    else:
        out.write(text_report(units, shown, args.directories, args.min_severity) + "\n")

    if args.exit_zero or not shown:
        return EXIT_CLEAN
    return EXIT_FINDINGS


if __name__ == "__main__":
    raise SystemExit(main())
