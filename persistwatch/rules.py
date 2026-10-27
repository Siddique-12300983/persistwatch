"""The detection rules.

Each rule is a function that takes a Unit (plus shared options) and returns a
list of Findings. Rules are deliberately small and independent so a noisy one
can be switched off with --disable without touching the others.
"""

import difflib
import os
import re
import shlex
import stat
import time
from typing import Callable, Dict, List, Optional

from .model import Finding, Unit

# Directories a legitimate packaged service almost never runs a binary from.
# Anything executable here is either world-writable by design or user-owned,
# which is exactly where an attacker drops a payload.
SUSPICIOUS_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/home/",
    "/root/",
    "/run/user/",
    "/var/www/",
    "/srv/ftp/",
    "/media/",
    "/mnt/",
)

# Shells and interpreters that turn a unit into an arbitrary-command runner.
INTERPRETERS = (
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "lua",
)

# Tools that pull code in from the network.
DOWNLOADERS = ("curl", "wget", "nc", "ncat", "netcat", "socat", "ftp", "tftp")

# Obfuscation and in-memory execution markers.
ENCODERS = ("base64", "xxd", "uudecode", "openssl enc", "eval", "memfd_create")

# A short list of real units whose names get imitated. Not exhaustive; it only
# needs to cover the names worth imitating for the lookalike check to be useful.
KNOWN_UNITS = (
    "systemd-logind.service",
    "systemd-journald.service",
    "systemd-resolved.service",
    "systemd-timesyncd.service",
    "systemd-udevd.service",
    "systemd-networkd.service",
    "dbus.service",
    "cron.service",
    "crond.service",
    "sshd.service",
    "ssh.service",
    "rsyslog.service",
    "polkit.service",
    "accounts-daemon.service",
    "NetworkManager.service",
    "apache2.service",
    "nginx.service",
    "docker.service",
    "containerd.service",
    "cups.service",
    "udisks2.service",
    "upower.service",
)

EXEC_PREFIX_CHARS = "-@+!:"


def strip_exec_prefixes(value: str) -> str:
    """Drop systemd's ExecStart prefix characters (-, @, +, !, !!, :)."""
    return value.lstrip(EXEC_PREFIX_CHARS).lstrip()


def split_command(value: str) -> List[str]:
    """Split an ExecStart value into argv, tolerating unbalanced quotes."""
    try:
        return shlex.split(value)
    except ValueError:
        return value.split()


def command_binary(value: str) -> str:
    """The binary an Exec* directive runs, with prefixes and argv removed."""
    parts = split_command(strip_exec_prefixes(value))
    return parts[0] if parts else ""


def _basename_no_version(path: str) -> str:
    return os.path.basename(path)


# Shell operators that separate commands inside a quoted "sh -c" string.
_SHELL_SPLIT = re.compile(r"[\s|;&()<>`$]+")


def shell_tokens(value: str) -> List[str]:
    """Every word in an Exec* value, looking inside quoted shell strings.

    shlex.split keeps `sh -c "curl http://x | sh"` as three arguments, so the
    downloader inside the quotes never shows up as its own token. This splits
    on shell operators as well so those nested commands are visible.
    """
    tokens = []
    for raw in _SHELL_SPLIT.split(strip_exec_prefixes(value)):
        word = raw.strip("\"'")
        if word:
            tokens.append(word)
    return tokens


def _is_interpreter(binary: str) -> bool:
    base = _basename_no_version(binary)
    return base in INTERPRETERS


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def rule_exec_from_suspicious_path(unit: Unit, options: Dict) -> List[Finding]:
    """ExecStart points into a world-writable or user-owned directory."""
    findings = []
    for directive, value in unit.exec_lines():
        binary = command_binary(value)
        if not binary.startswith("/"):
            continue
        for prefix in SUSPICIOUS_PREFIXES:
            if binary.startswith(prefix):
                findings.append(
                    Finding(
                        unit=unit.name,
                        path=unit.path,
                        rule="exec_from_suspicious_path",
                        severity="high",
                        technique="T1543.002",
                        message=(
                            "%s runs a binary from %s, which a packaged service "
                            "should not do" % (directive, prefix.rstrip("/"))
                        ),
                        evidence="%s=%s" % (directive, value),
                    )
                )
                break
    return findings


def rule_exec_relative_path(unit: Unit, options: Dict) -> List[Finding]:
    """ExecStart is not an absolute path, so it resolves against systemd's PATH."""
    findings = []
    for directive, value in unit.exec_lines():
        binary = command_binary(value)
        if not binary or binary.startswith("/") or binary.startswith("$"):
            continue
        findings.append(
            Finding(
                unit=unit.name,
                path=unit.path,
                rule="exec_relative_path",
                severity="medium",
                technique="T1543.002",
                message=(
                    "%s is a relative path, so which binary runs depends on PATH"
                    % directive
                ),
                evidence="%s=%s" % (directive, value),
            )
        )
    return findings


def rule_exec_shell_wrapped(unit: Unit, options: Dict) -> List[Finding]:
    """ExecStart hands a command string to a shell or interpreter."""
    findings = []
    for directive, value in unit.exec_lines():
        argv = split_command(strip_exec_prefixes(value))
        if not argv:
            continue
        if not _is_interpreter(argv[0]):
            continue
        inline = any(arg in ("-c", "-e", "--command") for arg in argv[1:])
        if not inline:
            continue
        findings.append(
            Finding(
                unit=unit.name,
                path=unit.path,
                rule="exec_shell_wrapped",
                severity="high",
                technique="T1059.004",
                message=(
                    "%s runs an inline command through %s instead of a real "
                    "executable" % (directive, _basename_no_version(argv[0]))
                ),
                evidence="%s=%s" % (directive, value),
            )
        )
    return findings


def rule_exec_network_download(unit: Unit, options: Dict) -> List[Finding]:
    """ExecStart fetches something over the network, usually to run it."""
    findings = []
    for directive, value in unit.exec_lines():
        names = {_basename_no_version(token) for token in shell_tokens(value)}
        hit = sorted(names.intersection(DOWNLOADERS))
        if not hit:
            continue
        piped = "|" in value or "&&" in value or ";" in value
        findings.append(
            Finding(
                unit=unit.name,
                path=unit.path,
                rule="exec_network_download",
                severity="high" if piped else "medium",
                technique="T1543.002",
                message=(
                    "%s calls %s%s"
                    % (
                        directive,
                        ", ".join(hit),
                        " and chains the output into another command" if piped else "",
                    )
                ),
                evidence="%s=%s" % (directive, value),
            )
        )
    return findings


def rule_exec_encoded_payload(unit: Unit, options: Dict) -> List[Finding]:
    """ExecStart decodes or evaluates its payload rather than naming a binary."""
    findings = []
    for directive, value in unit.exec_lines():
        lowered = value.lower()
        hit = [marker for marker in ENCODERS if marker in lowered]
        if not hit:
            continue
        findings.append(
            Finding(
                unit=unit.name,
                path=unit.path,
                rule="exec_encoded_payload",
                severity="high",
                technique="T1027",
                message=(
                    "%s contains %s, which hides what is actually executed"
                    % (directive, ", ".join(sorted(hit)))
                ),
                evidence="%s=%s" % (directive, value),
            )
        )
    return findings


def rule_ld_preload(unit: Unit, options: Dict) -> List[Finding]:
    """The unit injects a shared object into its own process."""
    findings = []
    for key in ("service.environment", "service.environmentfile"):
        for value in unit.options.get(key, []):
            if "LD_PRELOAD" in value or "LD_LIBRARY_PATH" in value:
                findings.append(
                    Finding(
                        unit=unit.name,
                        path=unit.path,
                        rule="ld_preload",
                        severity="high",
                        technique="T1574.006",
                        message="the unit sets a dynamic linker variable for its process",
                        evidence="%s=%s" % (unit.display(key), value),
                    )
                )
    return findings


def rule_world_writable_unit(unit: Unit, options: Dict) -> List[Finding]:
    """The unit file itself can be edited by any local user."""
    if not unit.mode:
        return []
    if not unit.mode & stat.S_IWOTH:
        return []
    return [
        Finding(
            unit=unit.name,
            path=unit.path,
            rule="world_writable_unit",
            severity="high",
            technique="T1543.002",
            message="the unit file is world-writable, so any user can change what root runs",
            evidence="mode %s" % oct(stat.S_IMODE(unit.mode)),
        )
    ]


def rule_world_writable_target(unit: Unit, options: Dict) -> List[Finding]:
    """The binary the unit runs can be replaced by any local user."""
    findings = []
    for directive, value in unit.exec_lines():
        binary = command_binary(value)
        if not binary.startswith("/"):
            continue
        try:
            info = os.stat(binary)
        except OSError:
            continue
        if not info.st_mode & stat.S_IWOTH:
            continue
        findings.append(
            Finding(
                unit=unit.name,
                path=unit.path,
                rule="world_writable_target",
                severity="high",
                technique="T1543.002",
                message="%s runs a world-writable binary" % directive,
                evidence="%s (mode %s)" % (binary, oct(stat.S_IMODE(info.st_mode))),
            )
        )
    return findings


def rule_recently_modified(unit: Unit, options: Dict) -> List[Finding]:
    """The unit changed inside the lookback window."""
    days = options.get("recent_days", 7)
    now = options.get("now") or time.time()
    if not unit.mtime or days <= 0:
        return []
    age_days = (now - unit.mtime) / 86400.0
    if age_days > days or age_days < 0:
        return []
    return [
        Finding(
            unit=unit.name,
            path=unit.path,
            rule="recently_modified",
            severity="low",
            technique="T1543.002",
            message="modified %.1f days ago, inside the %d day lookback" % (age_days, days),
            evidence=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unit.mtime)),
        )
    ]


def _seconds(value: str) -> Optional[float]:
    """Parse a systemd time span such as "30s", "5min", "1h 30min"."""
    units = {
        "us": 0.000001,
        "ms": 0.001,
        "s": 1.0,
        "sec": 1.0,
        "second": 1.0,
        "seconds": 1.0,
        "m": 60.0,
        "min": 60.0,
        "minute": 60.0,
        "minutes": 60.0,
        "h": 3600.0,
        "hr": 3600.0,
        "hour": 3600.0,
        "hours": 3600.0,
        "d": 86400.0,
        "day": 86400.0,
        "days": 86400.0,
        "w": 604800.0,
        "week": 604800.0,
        "weeks": 604800.0,
    }
    text = value.strip().lower().replace(" ", "")
    if not text:
        return None
    if text.isdigit():
        return float(text)
    total = 0.0
    number = ""
    suffix = ""
    matched = False
    for char in text + "\0":
        if char.isdigit() or char == ".":
            if suffix:
                if suffix not in units or not number:
                    return None
                total += float(number) * units[suffix]
                matched = True
                number = ""
                suffix = ""
            number += char
        elif char == "\0":
            break
        else:
            suffix += char
    if number:
        if suffix not in units:
            return None
        total += float(number) * units[suffix]
        matched = True
    return total if matched else None


def rule_timer_high_frequency(unit: Unit, options: Dict) -> List[Finding]:
    """A timer that fires often enough to work as a re-infection loop."""
    if unit.kind != "timer":
        return []
    threshold = options.get("timer_threshold_seconds", 120)
    findings = []
    for key in ("timer.onunitactivesec", "timer.onunitinactivesec", "timer.onbootsec",
                "timer.onstartupsec", "timer.onactivesec"):
        for value in unit.options.get(key, []):
            seconds = _seconds(value)
            if seconds is None or seconds > threshold:
                continue
            findings.append(
                Finding(
                    unit=unit.name,
                    path=unit.path,
                    rule="timer_high_frequency",
                    severity="medium",
                    technique="T1053.006",
                    message=(
                        "fires every %.0f seconds, which is often enough to restart a "
                        "payload as fast as it is killed" % seconds
                    ),
                    evidence="%s=%s" % (unit.display(key), value),
                )
            )
    for value in unit.options.get("timer.oncalendar", []):
        if value.strip().lower() in ("minutely", "*:*:00", "*:*"):
            findings.append(
                Finding(
                    unit=unit.name,
                    path=unit.path,
                    rule="timer_high_frequency",
                    severity="medium",
                    technique="T1053.006",
                    message="fires every minute on the calendar schedule",
                    evidence="OnCalendar=%s" % value,
                )
            )
    return findings


def rule_timer_without_unit(unit: Unit, options: Dict) -> List[Finding]:
    """A timer whose target unit is not in the scanned set."""
    if unit.kind != "timer":
        return []
    known = options.get("unit_names") or set()
    target = unit.first("Timer.Unit")
    if not target:
        target = unit.name[: -len(".timer")] + ".service"
        implied = True
    else:
        implied = False
    if target in known:
        return []
    return [
        Finding(
            unit=unit.name,
            path=unit.path,
            rule="timer_without_unit",
            severity="low",
            technique="T1053.006",
            message=(
                "triggers %s, which was not found in the scanned directory%s"
                % (target, " (implied by the timer name)" if implied else "")
            ),
            evidence="Unit=%s" % target if not implied else "implied: %s" % target,
        )
    ]


def rule_lookalike_name(unit: Unit, options: Dict) -> List[Finding]:
    """The unit name is a near miss for a real system unit."""
    name = unit.name.lstrip(".")
    if name in KNOWN_UNITS:
        return []
    matches = difflib.get_close_matches(name, KNOWN_UNITS, n=1, cutoff=0.88)
    if not matches:
        return []
    return [
        Finding(
            unit=unit.name,
            path=unit.path,
            rule="lookalike_name",
            severity="high",
            technique="T1036.005",
            message="the name is one or two characters away from the real unit %s" % matches[0],
            evidence="%s vs %s" % (name, matches[0]),
        )
    ]


def rule_hidden_unit_file(unit: Unit, options: Dict) -> List[Finding]:
    """A dotfile unit, which hides from a plain ls."""
    if not unit.name.startswith("."):
        return []
    return [
        Finding(
            unit=unit.name,
            path=unit.path,
            rule="hidden_unit_file",
            severity="medium",
            technique="T1564.001",
            message="the filename starts with a dot, so it does not show in a plain ls",
            evidence=unit.name,
        )
    ]


def rule_install_without_description(unit: Unit, options: Dict) -> List[Finding]:
    """An enabled unit with no Description, which packaged units always set."""
    if unit.kind not in ("service", "timer"):
        return []
    if not unit.options.get("install.wantedby") and not unit.options.get("install.requiredby"):
        return []
    if unit.first("Unit.Description"):
        return []
    return [
        Finding(
            unit=unit.name,
            path=unit.path,
            rule="install_without_description",
            severity="low",
            technique="T1543.002",
            message="set to start at boot but has no Description, unlike packaged units",
            evidence="[Install] present, Unit.Description missing",
        )
    ]


RULES: Dict[str, Callable[[Unit, Dict], List[Finding]]] = {
    "exec_from_suspicious_path": rule_exec_from_suspicious_path,
    "exec_relative_path": rule_exec_relative_path,
    "exec_shell_wrapped": rule_exec_shell_wrapped,
    "exec_network_download": rule_exec_network_download,
    "exec_encoded_payload": rule_exec_encoded_payload,
    "ld_preload": rule_ld_preload,
    "world_writable_unit": rule_world_writable_unit,
    "world_writable_target": rule_world_writable_target,
    "recently_modified": rule_recently_modified,
    "timer_high_frequency": rule_timer_high_frequency,
    "timer_without_unit": rule_timer_without_unit,
    "lookalike_name": rule_lookalike_name,
    "hidden_unit_file": rule_hidden_unit_file,
    "install_without_description": rule_install_without_description,
}
