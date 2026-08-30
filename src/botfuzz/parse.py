"""Parsers for Apache combined access.log lines."""

from __future__ import annotations

import gzip
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional


ACCESS_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\S+)'
    r'(?: "(?P<referer>.*?)" "(?P<ua>.*)")?\s*$'
)

ACCESS_LOOSE_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\].*?\s(?P<status>\d{3})\s"
)

ACCESS_TIME_FMTS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
)


@dataclass
class Event:
    raw: str
    time: Optional[datetime] = None
    ip: str = ""
    method: str = ""
    path: str = ""
    query: str = ""
    status: int = 0
    referer: str = ""
    ua: str = ""
    garbage: bool = False


def _parse_time(value: str, fmts: tuple[str, ...]) -> Optional[datetime]:
    for fmt in fmts:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _split_request(request: str) -> tuple[str, str, str]:
    if not request or request == "-":
        return "-", "-", ""
    parts = request.split()
    method = parts[0] if parts else "-"
    target = parts[1] if len(parts) > 1 else "-"
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""
    return method, path, query


def _looks_like_garbage(method: str, path: str) -> bool:
    if method in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "-", "PRI"):
        return False
    if method.startswith("\\x") or any(ord(ch) < 32 for ch in method[:8] if ch):
        return True
    if method not in ("GET", "POST", "HEAD", "OPTIONS") and len(method) > 12:
        return True
    return False


def parse_access_line(line: str) -> Optional[Event]:
    raw = line.rstrip("\n")
    match = ACCESS_RE.match(raw)
    if match:
        data = match.groupdict()
        method, path, query = _split_request(data.get("request") or "")
        return Event(
            raw=line,
            time=_parse_time(data["time"], ACCESS_TIME_FMTS),
            ip=data["ip"],
            method=method,
            path=path,
            query=query,
            status=int(data["status"]),
            referer=data.get("referer") or "",
            ua=data.get("ua") or "",
            garbage=_looks_like_garbage(method, path),
        )

    loose = ACCESS_LOOSE_RE.match(raw)
    if loose:
        return Event(
            raw=line,
            time=_parse_time(loose.group("time"), ACCESS_TIME_FMTS),
            ip=loose.group("ip"),
            status=int(loose.group("status")),
            garbage=True,
        )
    return None


def open_log_binary(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def iter_log_lines(path: str, start_offset: int = 0) -> Iterator[tuple[str, int]]:
    """Yield (line, offset_after_line). Stops before a final incomplete line."""
    gzipped = path.endswith(".gz")
    if gzipped:
        start_offset = 0
    with open_log_binary(path) as handle:
        if start_offset:
            handle.seek(start_offset)
        while True:
            line = handle.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                break
            text = line.decode("utf-8", errors="replace")
            yield text, handle.tell()


def list_log_files(directory: str, basename: str, rotated: bool) -> list[str]:
    """Return log files for basename (access.log) in directory."""
    current = os.path.join(directory, basename)
    files = []
    if os.path.isfile(current):
        files.append(current)
    if not rotated:
        return files
    numbered = os.path.join(directory, basename + ".1")
    if os.path.isfile(numbered):
        files.append(numbered)
    for name in sorted(os.listdir(directory)):
        if name.startswith(basename + ".") and name.endswith(".gz"):
            files.append(os.path.join(directory, name))
    return files
