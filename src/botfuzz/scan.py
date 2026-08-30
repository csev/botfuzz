"""Scan Apache access logs and merge probe paths into hits.csv."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .csvstore import Store
from .parse import iter_log_lines, list_log_files, parse_access_line
from .probes import is_probe


@dataclass
class ScanStats:
    files: int = 0
    skipped_files: int = 0
    lines: int = 0
    parsed: int = 0
    probes: int = 0
    new_paths: int = 0


def resolve_access_files(paths: list[str], directory: str | None, rotated: bool) -> list[str]:
    files: list[str] = []
    directories: list[str] = []
    if directory:
        directories.append(directory)
    for path in paths:
        if os.path.isdir(path):
            directories.append(path)
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise SystemExit(f"Not a log directory or file: {path}")
    if not files and not directories:
        directories.append("/var/log/apache2")
    for directory in directories:
        files.extend(list_log_files(directory, "access.log", rotated))
    if not files:
        raise SystemExit(
            "No access.log files found. Pass a directory like /tmp/apache2 or an access.log path."
        )
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    unique: list[str] = []
    for path in files:
        real = os.path.abspath(path)
        if real not in seen:
            seen.add(real)
            unique.append(real)
    return unique


def _start_offset(store: Store, path: str, inode: int, size: int) -> int | None:
    """Return byte offset to resume from, or None to skip the file entirely."""
    gzipped = path.endswith(".gz")
    wm = store.watermark_for(inode)
    if wm is None:
        return 0
    if gzipped:
        if wm.offset >= wm.size and wm.size == size:
            return None
        return 0
    if size < wm.offset:
        return 0
    if wm.offset >= size:
        return None
    return wm.offset


def scan_files(store: Store, files: list[str]) -> ScanStats:
    stats = ScanStats()
    for path in files:
        st = os.stat(path)
        inode, size = st.st_ino, st.st_size
        start = _start_offset(store, path, inode, size)
        if start is None:
            stats.skipped_files += 1
            continue
        stats.files += 1
        last_offset = start
        gzipped = path.endswith(".gz")
        for line, offset in iter_log_lines(path, start):
            last_offset = offset
            stats.lines += 1
            event = parse_access_line(line)
            if event is None:
                continue
            stats.parsed += 1
            if not is_probe(event):
                continue
            stats.probes += 1
            if store.note_hit(event.path, event.time, event.status, event.ip):
                stats.new_paths += 1
        end_size = os.stat(path).st_size
        if gzipped:
            last_offset = end_size
        store.set_watermark(inode, path, last_offset, end_size)
        store.save_hits()
        store.save_state()
    return stats
