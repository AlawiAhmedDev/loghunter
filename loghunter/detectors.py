"""Detection rules. Each rule takes the full event list and returns alerts.

Every alert is mapped to a MITRE ATT&CK technique so it can be triaged the
same way as in a SOC.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable
from urllib.parse import unquote_plus

from .models import Alert, Event

MAX_EVIDENCE = 5


@dataclass
class Config:
    bruteforce_threshold: int = 5      # failed SSH logins from one IP...
    window_seconds: int = 300          # ...within this sliding window
    spray_users: int = 5               # distinct usernames tried by one IP
    scan_threshold: int = 20           # 4xx responses from one IP in window
    critical_multiplier: int = 10      # threshold x this -> critical


def _peak_in_window(times: list, window: timedelta) -> int:
    """Largest number of events falling inside any sliding window."""
    best, left = 0, 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def _group_by_ip(events: list[Event], action: str | None = None,
                 source: str | None = None) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if action and e.action != action:
            continue
        if source and e.source != source:
            continue
        groups[e.ip].append(e)
    return groups


# --- SSH rules --------------------------------------------------------------

def detect_ssh_bruteforce(events: list[Event], cfg: Config) -> list[Alert]:
    alerts = []
    window = timedelta(seconds=cfg.window_seconds)
    for ip, evs in _group_by_ip(events, source="ssh").items():
        fails = [e for e in evs if e.action in ("ssh_failed", "ssh_invalid_user")
                 and not (e.action == "ssh_invalid_user" and _has_failed_twin(e, evs))]
        if not fails:
            continue
        peak = _peak_in_window([e.timestamp for e in fails], window)
        if peak < cfg.bruteforce_threshold:
            continue
        severity = "critical" if peak >= cfg.bruteforce_threshold * cfg.critical_multiplier else "high"
        alerts.append(Alert(
            rule="ssh_bruteforce",
            severity=severity,
            ip=ip,
            first_seen=fails[0].timestamp,
            last_seen=fails[-1].timestamp,
            count=len(fails),
            description=(f"{len(fails)} failed SSH logins "
                         f"(peak {peak} in {cfg.window_seconds}s)"),
            mitre="T1110.001 Brute Force: Password Guessing",
            evidence=[e.raw for e in fails[:MAX_EVIDENCE]],
        ))
    return alerts


def _has_failed_twin(invalid: Event, evs: list[Event]) -> bool:
    """sshd logs both 'Invalid user X' and 'Failed password for invalid user X'
    for the same attempt; count it once."""
    return any(e.action == "ssh_failed" and e.user == invalid.user
               and abs((e.timestamp - invalid.timestamp).total_seconds()) <= 5
               for e in evs)


def detect_password_spraying(events: list[Event], cfg: Config) -> list[Alert]:
    alerts = []
    for ip, evs in _group_by_ip(events, source="ssh").items():
        fails = [e for e in evs if e.action in ("ssh_failed", "ssh_invalid_user")]
        users = sorted({e.user for e in fails if e.user})
        if len(users) < cfg.spray_users:
            continue
        shown = ", ".join(users[:8]) + (" ..." if len(users) > 8 else "")
        alerts.append(Alert(
            rule="ssh_password_spraying",
            severity="high",
            ip=ip,
            first_seen=fails[0].timestamp,
            last_seen=fails[-1].timestamp,
            count=len(users),
            description=f"{len(users)} distinct usernames tried: {shown}",
            mitre="T1110.003 Brute Force: Password Spraying",
            evidence=[e.raw for e in fails[:MAX_EVIDENCE]],
        ))
    return alerts


def detect_success_after_bruteforce(events: list[Event], cfg: Config) -> list[Alert]:
    """A successful login from an IP that previously failed many times is the
    strongest signal in this tool: the password may have been guessed."""
    alerts = []
    for ip, evs in _group_by_ip(events, source="ssh").items():
        failures = 0
        for e in evs:
            if e.action == "ssh_failed":
                failures += 1
            elif e.action == "ssh_accepted" and failures >= cfg.bruteforce_threshold:
                prior = [x for x in evs if x.action == "ssh_failed"
                         and x.timestamp <= e.timestamp]
                alerts.append(Alert(
                    rule="ssh_success_after_bruteforce",
                    severity="critical",
                    ip=ip,
                    first_seen=prior[0].timestamp,
                    last_seen=e.timestamp,
                    count=failures,
                    description=(f"Successful login as '{e.user}' after "
                                 f"{failures} failed attempts - possible compromise"),
                    mitre="T1078 Valid Accounts",
                    evidence=[x.raw for x in prior[-(MAX_EVIDENCE - 1):]] + [e.raw],
                ))
                break
    return alerts


# --- Web rules --------------------------------------------------------------

WEB_PATTERNS: dict[str, tuple[str, str, re.Pattern]] = {
    "sql_injection": ("high", "T1190 Exploit Public-Facing Application", re.compile(
        r"(\bunion\b.{0,40}\bselect\b|\bor\b\s+\d+\s*=\s*\d+|'\s*or\s*'[^']*'\s*=\s*'"
        r"|\bsleep\s*\(\s*\d|benchmark\s*\(|information_schema|;\s*drop\s+table)",
        re.I)),
    "xss": ("high", "T1190 Exploit Public-Facing Application", re.compile(
        r"(<\s*script|javascript:|on(?:error|load|mouseover)\s*=|<\s*svg[^>]*on\w+\s*=)",
        re.I)),
    "path_traversal": ("high", "T1083 File and Directory Discovery", re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)", re.I)),
    "command_injection": ("high", "T1059 Command and Scripting Interpreter", re.compile(
        r"([;|&]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|\$\([^)]*\)|`[^`]+`)",
        re.I)),
    "sensitive_file_probe": ("medium", "T1595.003 Active Scanning: Wordlist Scanning",
                             re.compile(
        r"(/\.env\b|/\.git/|/\.aws/|/\.ssh/|/wp-config\.php|/phpmyadmin|/server-status"
        r"|/\.htpasswd|/backup\.(?:zip|sql|tar(?:\.gz)?)|/config\.(?:php|json|yml))",
        re.I)),
}

ESCALATE_ON_SUCCESS = {"sql_injection", "command_injection", "path_traversal"}

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|wpscan|nuclei"
    r"|feroxbuster|ffuf|hydra|acunetix|nessus|openvas|wfuzz)", re.I)


def _decode(path: str) -> str:
    # Decode twice to catch double URL-encoding (%252e%252e%252f -> ../)
    return unquote_plus(unquote_plus(path))


def detect_web_attacks(events: list[Event], cfg: Config) -> list[Alert]:
    hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.source != "web" or not e.path:
            continue
        decoded = _decode(e.path)
        for name, (_, _, pattern) in WEB_PATTERNS.items():
            if pattern.search(decoded):
                hits[(e.ip, name)].append(e)

    alerts = []
    for (ip, name), evs in hits.items():
        severity, mitre, _ = WEB_PATTERNS[name]
        succeeded = [e for e in evs if e.status and 200 <= e.status < 300]
        desc = f"{len(evs)} request(s) matching {name.replace('_', ' ')}"
        # A 2xx on XSS is normal (the page renders); on these it may mean success.
        if succeeded and name in ESCALATE_ON_SUCCESS:
            severity = "critical"
            desc += f" - {len(succeeded)} answered with 2xx, check whether it worked"
        alerts.append(Alert(
            rule=f"web_{name}",
            severity=severity,
            ip=ip,
            first_seen=evs[0].timestamp,
            last_seen=evs[-1].timestamp,
            count=len(evs),
            description=desc,
            mitre=mitre,
            evidence=[e.raw for e in evs[:MAX_EVIDENCE]],
        ))
    return alerts


def detect_web_scanning(events: list[Event], cfg: Config) -> list[Alert]:
    alerts = []
    window = timedelta(seconds=cfg.window_seconds)
    for ip, evs in _group_by_ip(events, source="web").items():
        errors = [e for e in evs if e.status and 400 <= e.status < 500]
        if not errors:
            continue
        peak = _peak_in_window([e.timestamp for e in errors], window)
        if peak < cfg.scan_threshold:
            continue
        distinct = len({e.path for e in errors})
        alerts.append(Alert(
            rule="web_directory_scanning",
            severity="medium",
            ip=ip,
            first_seen=errors[0].timestamp,
            last_seen=errors[-1].timestamp,
            count=len(errors),
            description=(f"{len(errors)} client errors on {distinct} distinct paths "
                         f"(peak {peak} in {cfg.window_seconds}s)"),
            mitre="T1595.003 Active Scanning: Wordlist Scanning",
            evidence=[e.raw for e in errors[:MAX_EVIDENCE]],
        ))
    return alerts


def detect_scanner_user_agents(events: list[Event], cfg: Config) -> list[Alert]:
    hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.source == "web" and e.user_agent:
            m = SCANNER_UA.search(e.user_agent)
            if m:
                hits[(e.ip, m.group(1).lower())].append(e)
    return [
        Alert(
            rule="web_scanner_user_agent",
            severity="medium",
            ip=ip,
            first_seen=evs[0].timestamp,
            last_seen=evs[-1].timestamp,
            count=len(evs),
            description=f"{len(evs)} request(s) from offensive tool '{tool}'",
            mitre="T1595 Active Scanning",
            evidence=[e.raw for e in evs[:MAX_EVIDENCE]],
        )
        for (ip, tool), evs in hits.items()
    ]


RULES: dict[str, Callable[[list[Event], Config], list[Alert]]] = {
    "ssh_bruteforce": detect_ssh_bruteforce,
    "ssh_password_spraying": detect_password_spraying,
    "ssh_success_after_bruteforce": detect_success_after_bruteforce,
    "web_attacks": detect_web_attacks,
    "web_directory_scanning": detect_web_scanning,
    "web_scanner_user_agent": detect_scanner_user_agents,
}


def run_all(events: list[Event], cfg: Config | None = None) -> list[Alert]:
    cfg = cfg or Config()
    alerts: list[Alert] = []
    for rule in RULES.values():
        alerts.extend(rule(events, cfg))
    alerts.sort(key=lambda a: (-a.severity_rank, a.first_seen))
    return alerts
