"""Render findings as a readable report or as JSON."""

import json
from collections import Counter, OrderedDict
from typing import Dict, List, Sequence

from .model import Finding, Unit, severity_rank

MARKERS = {"high": "[!!]", "medium": "[!]", "low": "[-]"}

TECHNIQUE_NAMES = {
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1053.006": "Scheduled Task/Job: Systemd Timers",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1564.001": "Hide Artifacts: Hidden Files and Directories",
    "T1574.006": "Hijack Execution Flow: Dynamic Linker Hijacking",
    "T1027": "Obfuscated Files or Information",
}


def _rule(width: int = 72) -> str:
    return "-" * width


def text_report(
    units: Sequence[Unit],
    findings: Sequence[Finding],
    directories: Sequence[str],
    minimum: str = "low",
) -> str:
    lines: List[str] = []
    lines.append("persistwatch report")
    lines.append(_rule())
    lines.append("scanned      : %s" % ", ".join(directories))
    lines.append("units parsed : %d" % len(units))
    counts = Counter(f.severity for f in findings)
    lines.append(
        "findings     : %d  (high %d, medium %d, low %d)"
        % (len(findings), counts["high"], counts["medium"], counts["low"])
    )
    lines.append("min severity : %s" % minimum)
    lines.append("")

    if not findings:
        lines.append("No findings. Every parsed unit looked ordinary.")
        lines.append("")
        return "\n".join(lines)

    by_unit: "OrderedDict[str, List[Finding]]" = OrderedDict()
    for finding in findings:
        by_unit.setdefault(finding.unit, []).append(finding)

    for unit_name, unit_findings in by_unit.items():
        worst = max(unit_findings, key=lambda f: severity_rank(f.severity))
        lines.append("%s %s" % (MARKERS.get(worst.severity, "[-]"), unit_name))
        lines.append("     %s" % unit_findings[0].path)
        for finding in unit_findings:
            lines.append(
                "     %-6s %-28s %s"
                % (finding.severity, finding.rule, finding.technique)
            )
            lines.append("            %s" % finding.message)
            if finding.evidence:
                lines.append("            evidence: %s" % finding.evidence)
        lines.append("")

    techniques = sorted({f.technique for f in findings})
    lines.append("MITRE ATT&CK techniques seen")
    lines.append(_rule())
    for technique in techniques:
        lines.append("  %-12s %s" % (technique, TECHNIQUE_NAMES.get(technique, "")))
    lines.append("")

    parse_problems = [u for u in units if u.parse_errors]
    if parse_problems:
        lines.append("Parse warnings")
        lines.append(_rule())
        for unit in parse_problems:
            for error in unit.parse_errors:
                lines.append("  %s: %s" % (unit.name, error))
        lines.append("")

    return "\n".join(lines)


def json_report(
    units: Sequence[Unit],
    findings: Sequence[Finding],
    directories: Sequence[str],
    minimum: str = "low",
) -> Dict:
    counts = Counter(f.severity for f in findings)
    return {
        "tool": "persistwatch",
        "scanned": list(directories),
        "min_severity": minimum,
        "summary": {
            "units_parsed": len(units),
            "findings": len(findings),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "units_with_findings": len({f.unit for f in findings}),
        },
        "techniques": sorted({f.technique for f in findings}),
        "findings": [f.as_dict() for f in findings],
        "parse_warnings": [
            {"unit": u.name, "path": u.path, "errors": u.parse_errors}
            for u in units
            if u.parse_errors
        ],
    }


def json_text(*args, **kwargs) -> str:
    return json.dumps(json_report(*args, **kwargs), indent=2, sort_keys=False)
