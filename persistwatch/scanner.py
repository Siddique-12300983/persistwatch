"""Run the rules over a set of parsed units."""

import time
from typing import Dict, Iterable, List, Optional, Sequence

from .model import Finding, Unit, severity_rank
from .parser import scan_directory
from .rules import RULES


def default_options() -> Dict:
    return {
        "recent_days": 7,
        "timer_threshold_seconds": 120,
        "now": None,
        "unit_names": set(),
    }


def run_rules(
    units: Sequence[Unit],
    options: Optional[Dict] = None,
    disabled: Iterable[str] = (),
) -> List[Finding]:
    """Apply every enabled rule to every unit."""
    opts = default_options()
    if options:
        opts.update(options)
    if opts.get("now") is None:
        opts["now"] = time.time()
    # Rules such as timer_without_unit need to know the whole scanned set.
    opts["unit_names"] = {unit.name for unit in units}

    skip = set(disabled)
    unknown = skip.difference(RULES)
    if unknown:
        raise ValueError("unknown rule(s): %s" % ", ".join(sorted(unknown)))

    findings: List[Finding] = []
    for unit in units:
        for name, rule in RULES.items():
            if name in skip:
                continue
            findings.extend(rule(unit, opts))
    findings.sort(key=lambda f: (-severity_rank(f.severity), f.unit, f.rule))
    return findings


def scan(
    directories: Sequence[str],
    options: Optional[Dict] = None,
    disabled: Iterable[str] = (),
    recursive: bool = True,
):
    """Parse every unit under the given directories, then run the rules.

    Returns (units, findings).
    """
    units: List[Unit] = []
    for directory in directories:
        units.extend(scan_directory(directory, recursive=recursive))
    units.sort(key=lambda u: u.path)
    return units, run_rules(units, options=options, disabled=disabled)


def filter_by_severity(findings: Sequence[Finding], minimum: str) -> List[Finding]:
    floor = severity_rank(minimum)
    return [f for f in findings if severity_rank(f.severity) >= floor]
