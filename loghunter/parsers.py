"""Parsers for OpenSSH (auth.log / secure) and Apache/Nginx access logs.

Only the standard library is used. Month names are mapped manually so that
parsing does not depend on the system locale (``%b`` breaks on a French or
Arabic locale).
"""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .models import Event

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

# --- SSH -------------------------------------------------------------------

_SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

_SSH_FAILED = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_SSH_INVALID = re.compile(
    r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"
)

# --- Web (Apache / Nginx "combined" or "common" format) ---------------------

_WEB = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[0-9.]+)?" '
    r'(?P<status>\d{3}) (?:\d+|-)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
_WEB_TS = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?: (?P<tz>[+-]\d{4}))?"
)


def _to_naive_utc(dt: datetime) -> datetime:
    """Normalise aware datetimes to naive UTC so all events are comparable."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _parse_syslog_ts(mon: str, day: str, time: str, year: int) -> datetime:
    h, m, s = (int(x) for x in time.split(":"))
    return datetime(year, MONTHS[mon], int(day), h, m, s)


def _parse_iso_ts(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", ts):  # +0100 -> +01:00 for fromisoformat
        ts = ts[:-2] + ":" + ts[-2:]
    return _to_naive_utc(datetime.fromisoformat(ts))


def _parse_web_ts(ts: str) -> datetime | None:
    m = _WEB_TS.match(ts)
    if not m or m["mon"] not in MONTHS:
        return None
    dt = datetime(int(m["year"]), MONTHS[m["mon"]], int(m["day"]),
                  int(m["h"]), int(m["m"]), int(m["s"]))
    if m["tz"]:
        sign = 1 if m["tz"][0] == "+" else -1
        offset = sign * (int(m["tz"][1:3]) * 60 + int(m["tz"][3:5]))
        dt = dt - timedelta(minutes=offset)
    return dt


def parse_ssh_line(line: str, year: int | None = None) -> Event | None:
    """Parse one sshd line. Returns ``None`` for lines that are not relevant."""
    line = line.rstrip("\n")
    year = year or datetime.now().year

    m = _SYSLOG_PREFIX.match(line)
    if m:
        if m["mon"] not in MONTHS:
            return None
        ts = _parse_syslog_ts(m["mon"], m["day"], m["time"], year)
    else:
        m = _ISO_PREFIX.match(line)
        if not m:
            return None
        ts = _parse_iso_ts(m["ts"])
    msg = m["msg"]

    if (f := _SSH_FAILED.match(msg)):
        return Event(ts, "ssh", "ssh_failed", f["ip"], user=f["user"] or None, raw=line)
    if (a := _SSH_ACCEPTED.match(msg)):
        return Event(ts, "ssh", "ssh_accepted", a["ip"], user=a["user"], raw=line)
    if (i := _SSH_INVALID.match(msg)):
        return Event(ts, "ssh", "ssh_invalid_user", i["ip"], user=i["user"] or None, raw=line)
    return None


def parse_web_line(line: str) -> Event | None:
    """Parse one Apache/Nginx access-log line."""
    line = line.rstrip("\n")
    m = _WEB.match(line)
    if not m:
        return None
    ts = _parse_web_ts(m["ts"])
    if ts is None:
        return None
    return Event(
        timestamp=ts,
        source="web",
        action="http_request",
        ip=m["ip"],
        method=m["method"],
        path=m["path"],
        status=int(m["status"]),
        user_agent=m["ua"],
        raw=line,
    )


@dataclass
class ParseStats:
    files: int = 0
    lines: int = 0
    parsed: int = 0
    by_source: dict[str, int] = field(default_factory=dict)

    @property
    def skipped(self) -> int:
        return self.lines - self.parsed


def _open(path: Path) -> Iterator[str]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        yield from fh


def parse_lines(lines: Iterable[str], year: int | None = None,
                stats: ParseStats | None = None) -> list[Event]:
    """Parse lines of any supported format, detecting the format per line."""
    events: list[Event] = []
    for line in lines:
        if not line.strip():
            continue
        if stats:
            stats.lines += 1
        ev = parse_ssh_line(line, year) or parse_web_line(line)
        if ev:
            events.append(ev)
            if stats:
                stats.parsed += 1
                stats.by_source[ev.source] = stats.by_source.get(ev.source, 0) + 1
    return events


def parse_files(paths: Iterable[str | Path], year: int | None = None
                ) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    events: list[Event] = []
    for p in paths:
        stats.files += 1
        events.extend(parse_lines(_open(Path(p)), year, stats))
    events.sort(key=lambda e: e.timestamp)
    return events, stats
