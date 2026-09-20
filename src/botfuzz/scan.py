"""Scan Apache access logs and merge probe paths into hits.csv."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .csvstore import Store, is_allowed
from .parse import iter_log_lines, list_log_files, parse_access_line
from .presets import covers_path
from .probes import is_probe

# Keep stdout moving so long --rotated runs do not look hung / time out SSH.
_PROGRESS_EVERY = 60.0


@dataclass
class ScanStats:
    files: int = 0
    skipped_files: int = 0
    lines: int = 0
    parsed: int = 0
    probes: int = 0
    preset_probes: int = 0
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


def _fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} B"


def _progress(msg: str) -> None:
    print(msg, flush=True)


def scan_files(store: Store, files: list[str]) -> ScanStats:
    stats = ScanStats()
    enabled = store.enabled_presets()
    total = len(files)
    _progress(f"Scanning {total} log file(s)...")
    for i, path in enumerate(files, start=1):
        st = os.stat(path)
        inode, size = st.st_ino, st.st_size
        label = os.path.basename(path)
        prefix = f"  [{i}/{total}]"
        start = _start_offset(store, path, inode, size)
        if start is None:
            stats.skipped_files += 1
            _progress(f"{prefix} skip {label} (already read)")
            continue
        stats.files += 1
        resume = f", resume at byte {start}" if start else ""
        _progress(f"{prefix} {label} ({_fmt_size(size)}{resume})")
        last_offset = start
        gzipped = path.endswith(".gz")
        file_lines = 0
        file_probes = 0
        file_new = 0
        last_report = time.monotonic()
        for line, offset in iter_log_lines(path, start):
            last_offset = offset
            stats.lines += 1
            file_lines += 1
            event = parse_access_line(line)
            if event is not None:
                stats.parsed += 1
                if is_probe(event):
                    stats.probes += 1
                    file_probes += 1
                    if covers_path(event.path, enabled):
                        stats.preset_probes += 1
                    elif not is_allowed(event.path, store.allow):
                        if store.note_hit(event.path, event.time, event.status, event.ip):
                            stats.new_paths += 1
                            file_new += 1
            now = time.monotonic()
            if now - last_report >= _PROGRESS_EVERY:
                _progress(
                    f"    ... {file_lines} lines, {file_probes} probes, {file_new} new"
                )
                last_report = now
        end_size = os.stat(path).st_size
        if gzipped:
            last_offset = end_size
        store.set_watermark(inode, path, last_offset, end_size)
        _progress(f"{prefix} saving hits after {label}...")
        store.save_hits()
        store.save_state()
        _progress(
            f"{prefix} done {label}: {file_lines} lines, {file_probes} probes, {file_new} new"
        )
    return stats
