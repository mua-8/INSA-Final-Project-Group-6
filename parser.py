"""ThreatLens - OpenSSH authentication log parser (RSD FR-02 to FR-06).

Turns raw syslog-style sshd lines into structured events.

Design notes
------------
* Logs are hostile input: attackers control usernames, so every extracted
  field is length-limited and the source IP is validated.
* Malformed lines never crash parsing; they are counted and reported (FR-05).
* The raw line is kept with every event for traceability (FR-04).
* Syslog timestamps have no year or timezone, so the caller supplies the year.
* Duplicate lines are skipped on request (FR-06) using a hash of the raw line.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional

MAX_FIELD_LEN = 128      # limit for usernames, hostnames, methods
MAX_LINE_LEN = 2048      # lines longer than this are treated as malformed

# Event types
FAILED_LOGIN = "failed_login"
INVALID_USER = "invalid_user"
ACCEPTED_LOGIN = "accepted_login"
DISCONNECT = "disconnect"

# Outcomes
OUTCOME_FAILURE = "failure"
OUTCOME_SUCCESS = "success"
OUTCOME_DISCONNECT = "disconnect"

# "Oct 24 13:01:02 myhost sshd[1234]: <message>"
_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

_ADDR = r"(?P<ip>[0-9A-Fa-f:.]+)\s+port\s+(?P<port>\d+)"

# Each pattern: (regex, event_type, outcome)
_MESSAGE_PATTERNS = [
    (re.compile(
        rf"^Failed (?P<method>\S+) for invalid user (?P<user>.+?) from {_ADDR}"),
        INVALID_USER, OUTCOME_FAILURE),
    (re.compile(
        rf"^Failed (?P<method>\S+) for (?P<user>.+?) from {_ADDR}"),
        FAILED_LOGIN, OUTCOME_FAILURE),
    (re.compile(
        rf"^Invalid user (?P<user>.*?) from {_ADDR}"),
        INVALID_USER, OUTCOME_FAILURE),
    (re.compile(
        rf"^Accepted (?P<method>\S+) for (?P<user>.+?) from {_ADDR}"),
        ACCEPTED_LOGIN, OUTCOME_SUCCESS),
    (re.compile(
        rf"^Disconnected from (?:authenticating |invalid )?user (?P<user>.+?) {_ADDR}"),
        DISCONNECT, OUTCOME_DISCONNECT),
    (re.compile(
        rf"^Received disconnect from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"),
        DISCONNECT, OUTCOME_DISCONNECT),
    (re.compile(
        rf"^Connection closed by (?:authenticating |invalid )?(?:user (?P<user>.+?) )?{_ADDR}"),
        DISCONNECT, OUTCOME_DISCONNECT),
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass
class Event:
    timestamp: datetime
    host: str
    source_ip: str
    port: Optional[int]
    username: Optional[str]
    method: Optional[str]
    event_type: str
    outcome: str
    raw_line: str
    line_hash: str


@dataclass
class ParseResult:
    events: list = field(default_factory=list)
    total_lines: int = 0
    malformed_count: int = 0
    skipped_count: int = 0       # valid syslog lines we do not model (e.g. non-sshd)
    duplicate_count: int = 0
    errors: list = field(default_factory=list)  # (line_number, reason)


class ParseError(ValueError):
    """Raised internally for a line that cannot be turned into an event."""


def _clean(value: Optional[str]) -> Optional[str]:
    """Strip and length-limit an untrusted field."""
    if value is None:
        return None
    value = value.strip()
    if len(value) > MAX_FIELD_LEN:
        value = value[:MAX_FIELD_LEN]
    return value or None


def _hash_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()


def parse_line(line: str, year: int) -> Optional[Event]:
    """Parse one log line.

    Returns an Event, or None when the line is well-formed syslog but not an
    sshd authentication message we model. Raises ParseError when malformed.
    """
    raw = line.rstrip("\r\n")
    if len(raw) > MAX_LINE_LEN:
        raise ParseError("line too long")

    header = _HEADER.match(raw)
    if not header:
        raise ParseError("not a syslog-formatted line")

    month = _MONTHS.get(header["month"])
    if month is None:
        raise ParseError("invalid month")
    try:
        hh, mm, ss = (int(x) for x in header["time"].split(":"))
        timestamp = datetime(year, month, int(header["day"]), hh, mm, ss)
    except ValueError:
        raise ParseError("invalid date or time")

    if not header["proc"].startswith("sshd"):
        return None

    message = header["msg"]
    for pattern, event_type, outcome in _MESSAGE_PATTERNS:
        match = pattern.match(message)
        if not match:
            continue
        groups = match.groupdict()

        try:
            ip = str(ipaddress.ip_address(groups["ip"]))
        except ValueError:
            raise ParseError("invalid source IP")

        port = int(groups["port"])
        if not 0 < port <= 65535:
            raise ParseError("invalid port")

        return Event(
            timestamp=timestamp,
            host=_clean(header["host"]) or "unknown",
            source_ip=ip,
            port=port,
            username=_clean(groups.get("user")),
            method=_clean(groups.get("method")),
            event_type=event_type,
            outcome=outcome,
            raw_line=raw,
            line_hash=_hash_line(raw),
        )

    return None  # an sshd line we do not model


def parse_lines(lines: Iterable[str], year: int,
                skip_duplicates: bool = True) -> ParseResult:
    """Parse many lines, counting malformed ones instead of crashing."""
    result = ParseResult()
    seen: set = set()

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        result.total_lines += 1
        try:
            event = parse_line(line, year)
        except ParseError as exc:
            result.malformed_count += 1
            result.errors.append((number, str(exc)))
            continue

        if event is None:
            result.skipped_count += 1
            continue

        if skip_duplicates:
            if event.line_hash in seen:
                result.duplicate_count += 1
                continue
            seen.add(event.line_hash)

        result.events.append(event)

    return result


def parse_text(text: str, year: int, skip_duplicates: bool = True) -> ParseResult:
    return parse_lines(text.splitlines(), year, skip_duplicates)


def parse_file(path: str, year: int, skip_duplicates: bool = True) -> ParseResult:
    # errors="replace" so binary junk in a log cannot crash ingestion
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle, year, skip_duplicates)


if __name__ == "__main__":
    import sys
    from collections import Counter

    if len(sys.argv) < 2:
        sys.exit("usage: python -m backend.parser <logfile> [year]")
    yr = int(sys.argv[2]) if len(sys.argv) > 2 else datetime.now().year
    res = parse_file(sys.argv[1], yr)
    print(f"lines={res.total_lines} events={len(res.events)} "
          f"malformed={res.malformed_count} skipped={res.skipped_count} "
          f"duplicates={res.duplicate_count}")
    print(dict(Counter(e.event_type for e in res.events)))
    for n, why in res.errors:
        print(f"  line {n}: {why}")
