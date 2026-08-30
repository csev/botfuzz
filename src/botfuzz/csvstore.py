"""Sorted CSV stores for probe hits, already-ruled paths, and scan watermarks."""

from __future__ import annotations

import csv
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

HITS_FIELDS = ["path", "count", "first_seen", "last_seen", "status", "sample_ip"]
RULED_FIELDS = ["path", "ruled_at", "count_when_ruled", "rule"]
RULES_FIELDS = ["name", "cloudflare_name", "created", "updated", "md5", "frozen", "chars", "prefix"]
ALLOW_FIELDS = ["path", "note"]
PENDING_FIELDS = ["path"]
PRESETS_FIELDS = ["name", "enabled"]
STATE_FILENAME = "state.json"
HITS_FILENAME = "hits.csv"
RULED_FILENAME = "ruled.csv"
RULES_FILENAME = "rules.csv"
ALLOW_FILENAME = "allow.csv"
PENDING_FILENAME = "pending.csv"
PRESETS_FILENAME = "presets.csv"
PRESETS_SAMPLE_FILENAME = "presets.sample.csv"


def repo_root() -> str:
    # src/botfuzz/csvstore.py -> repo root
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def sample_presets_path() -> str:
    return os.path.join(repo_root(), PRESETS_SAMPLE_FILENAME)


def _parse_dt(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _fmt_dt(value: Optional[datetime]) -> str:
    if value is None:
        return ""
    return value.isoformat()


@dataclass
class Hit:
    path: str
    count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: int = 0
    sample_ip: str = ""

    def add(self, when: Optional[datetime], status: int, ip: str, n: int = 1) -> None:
        self.count += n
        if when is not None:
            if self.first_seen is None or when < self.first_seen:
                self.first_seen = when
            if self.last_seen is None or when > self.last_seen:
                self.last_seen = when
                if status:
                    self.status = status
                if ip:
                    self.sample_ip = ip
        elif status and not self.status:
            self.status = status
        if ip and not self.sample_ip:
            self.sample_ip = ip


@dataclass
class Ruled:
    path: str
    ruled_at: str = ""
    count_when_ruled: int = 0
    rule: str = ""


@dataclass
class RuleMeta:
    name: str
    cloudflare_name: str = ""
    created: str = ""
    updated: str = ""
    md5: str = ""
    frozen: bool = False
    prefix: str = ""
    chars: int = 0


@dataclass
class Allowed:
    path: str
    note: str = ""


def is_allowed(path: str, allow: dict[str, Allowed]) -> bool:
    """Exact path, or a prefix entry that ends with /."""
    if not path or not allow:
        return False
    if path in allow:
        return True
    for key in allow:
        if not key.endswith("/"):
            continue
        if path.startswith(key) or path == key.rstrip("/"):
            return True
    return False


@dataclass
class FileWatermark:
    path: str = ""
    offset: int = 0
    size: int = 0


@dataclass
class Store:
    data_dir: str
    hits: dict[str, Hit] = field(default_factory=dict)
    ruled: dict[str, Ruled] = field(default_factory=dict)
    rules: dict[str, RuleMeta] = field(default_factory=dict)
    allow: dict[str, Allowed] = field(default_factory=dict)
    pending: dict[str, None] = field(default_factory=dict)
    preset_flags: dict[str, bool] = field(default_factory=dict)
    watermarks: dict[str, FileWatermark] = field(default_factory=dict)

    @property
    def hits_path(self) -> str:
        return os.path.join(self.data_dir, HITS_FILENAME)

    @property
    def ruled_path(self) -> str:
        return os.path.join(self.data_dir, RULED_FILENAME)

    @property
    def rules_path(self) -> str:
        return os.path.join(self.data_dir, RULES_FILENAME)

    @property
    def allow_path(self) -> str:
        return os.path.join(self.data_dir, ALLOW_FILENAME)

    @property
    def pending_path(self) -> str:
        return os.path.join(self.data_dir, PENDING_FILENAME)

    @property
    def presets_path(self) -> str:
        return os.path.join(self.data_dir, PRESETS_FILENAME)

    @property
    def state_path(self) -> str:
        return os.path.join(self.data_dir, STATE_FILENAME)

    def load(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        self.hits = _read_hits(self.hits_path)
        self.ruled = _read_ruled(self.ruled_path)
        self.rules = _read_rules(self.rules_path)
        self.allow = _read_allow(self.allow_path)
        self.pending = _read_pending(self.pending_path)
        if not os.path.isfile(self.presets_path):
            sample = sample_presets_path()
            if os.path.isfile(sample):
                shutil.copy(sample, self.presets_path)
        self.preset_flags = _read_preset_flags(self.presets_path)
        if not os.path.isfile(self.presets_path):
            self.save_presets()
        self.watermarks = _read_watermarks(self.state_path)

    def save_hits(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        rows = sorted(self.hits.values(), key=lambda h: h.path)
        with open(self.hits_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=HITS_FIELDS)
            writer.writeheader()
            for hit in rows:
                writer.writerow({
                    "path": hit.path,
                    "count": hit.count,
                    "first_seen": _fmt_dt(hit.first_seen),
                    "last_seen": _fmt_dt(hit.last_seen),
                    "status": hit.status,
                    "sample_ip": hit.sample_ip,
                })

    def save_ruled(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        rows = sorted(self.ruled.values(), key=lambda r: r.path)
        with open(self.ruled_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=RULED_FIELDS)
            writer.writeheader()
            for item in rows:
                writer.writerow({
                    "path": item.path,
                    "ruled_at": item.ruled_at,
                    "count_when_ruled": item.count_when_ruled,
                    "rule": item.rule,
                })

    def save_rules(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        from .rule import rule_number as _rule_number
        rows = sorted(self.rules.values(), key=lambda r: (_rule_number(r.name), r.name))
        with open(self.rules_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=RULES_FIELDS)
            writer.writeheader()
            for item in rows:
                writer.writerow({
                    "name": item.name,
                    "cloudflare_name": item.cloudflare_name,
                    "created": item.created,
                    "updated": item.updated,
                    "md5": item.md5,
                    "frozen": "1" if item.frozen else "0",
                    "chars": item.chars,
                    "prefix": item.prefix,
                })

    def save_allow(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        rows = sorted(self.allow.values(), key=lambda a: a.path)
        with open(self.allow_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=ALLOW_FIELDS)
            writer.writeheader()
            for item in rows:
                writer.writerow({
                    "path": item.path,
                    "note": item.note,
                })

    def save_presets(self) -> None:
        from .presets import PRESET_ORDER, default_enabled

        os.makedirs(self.data_dir, exist_ok=True)
        flags = default_enabled()
        flags.update(self.preset_flags)
        self.preset_flags = flags
        with open(self.presets_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=PRESETS_FIELDS)
            writer.writeheader()
            for name in PRESET_ORDER:
                writer.writerow({
                    "name": name,
                    "enabled": "1" if flags.get(name) else "0",
                })

    def save_state(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        payload = {
            "inodes": {
                ino: {"path": wm.path, "offset": wm.offset, "size": wm.size}
                for ino, wm in self.watermarks.items()
            }
        }
        with open(self.state_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def watermark_for(self, inode: int) -> Optional[FileWatermark]:
        return self.watermarks.get(str(inode))

    def set_watermark(self, inode: int, path: str, offset: int, size: int) -> None:
        self.watermarks[str(inode)] = FileWatermark(path=path, offset=offset, size=size)

    def note_hit(self, path: str, when: Optional[datetime], status: int, ip: str) -> bool:
        """Merge one probe. Returns True if this path is new."""
        existing = self.hits.get(path)
        if existing is None:
            hit = Hit(path=path)
            hit.add(when, status, ip)
            self.hits[path] = hit
            return True
        existing.add(when, status, ip)
        return False

    def enabled_presets(self) -> dict[str, bool]:
        from .presets import default_enabled

        flags = default_enabled()
        flags.update(self.preset_flags)
        return flags

    def unmarked_hits(self) -> list[Hit]:
        from .presets import covers_path
        from .probes import is_legit_path, is_probe_path

        enabled = self.enabled_presets()
        return [
            h for h in self.hits.values()
            if h.path not in self.ruled
            and h.path not in self.pending
            and not is_allowed(h.path, self.allow)
            and not covers_path(h.path, enabled)
            and not is_legit_path(h.path)
            and (not h.status or is_probe_path(h.path, h.status))
        ]

    def preset_hits(self) -> list[Hit]:
        from .presets import covers_path

        enabled = self.enabled_presets()
        return [h for h in self.hits.values() if covers_path(h.path, enabled)]

    def set_preset(self, name: str, enabled: bool) -> None:
        from .presets import PRESETS

        if name not in PRESETS:
            raise ValueError(f"Unknown preset: {name}")
        self.preset_flags[name] = enabled

    def top_unmarked(self, n: int) -> list[Hit]:
        hits = self.unmarked_hits()
        hits.sort(key=lambda h: (-h.count, h.path))
        return hits[:n]

    def add_allow(self, path: str, note: str = "") -> bool:
        """Add a path to the allow list. Returns True if it was new."""
        if path in self.allow:
            if note:
                self.allow[path].note = note
            return False
        self.allow[path] = Allowed(path=path, note=note)
        return True

    def add_pending(self, path: str) -> bool:
        """Queue a path to block on the next emit. Returns True if it was new."""
        if path in self.pending or path in self.ruled:
            return False
        self.pending[path] = None
        return True

    def save_pending(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.pending_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=PENDING_FIELDS)
            writer.writeheader()
            for path in sorted(self.pending):
                writer.writerow({"path": path})

    def clear_pending(self) -> None:
        self.pending = {}
        self.save_pending()

    def mark_ruled(self, paths: list[str], rule_name: str, when: Optional[datetime] = None) -> int:
        from .presets import covers_path
        from .probes import is_legit_path

        stamped = (when or datetime.now(timezone.utc)).isoformat()
        added = 0
        for path in paths:
            if path in self.ruled or is_allowed(path, self.allow):
                continue
            if covers_path(path, self.enabled_presets()):
                continue
            if is_legit_path(path):
                continue
            hit = self.hits.get(path)
            self.ruled[path] = Ruled(
                path=path,
                ruled_at=stamped,
                count_when_ruled=hit.count if hit else 0,
                rule=rule_name,
            )
            added += 1
        return added

    def sync_botrules(self, botrules: list, when: Optional[datetime] = None) -> int:
        """Persist named rules and assign any new paths to their rule."""
        from .rule import BotRule

        stamped = when or datetime.now(timezone.utc)
        added = 0
        self.rules = {}
        for br in botrules:
            if not isinstance(br, BotRule):
                continue
            self.rules[br.name] = RuleMeta(
                name=br.name,
                cloudflare_name=br.cloudflare_name,
                created=br.created,
                updated=br.updated,
                md5=br.md5,
                frozen=br.frozen,
                prefix=br.prefix,
                chars=br.chars,
            )
            added += self.mark_ruled(br.paths, br.name, stamped)
        self.save_rule_outputs(botrules)
        return added

    def save_rule_outputs(self, botrules: list) -> None:
        """Write paste-ready expressions so open rules can grow across runs."""
        from .rule import MAX_EXPR, BotRule

        outdir = os.path.join(self.data_dir, "rules")
        os.makedirs(outdir, exist_ok=True)
        for br in botrules:
            if not isinstance(br, BotRule):
                continue
            path = os.path.join(outdir, f"{br.name}.txt")
            status = "FROZEN" if br.frozen else "OPEN"
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"# {br.cloudflare_name}\n")
                handle.write(
                    f"# {br.chars}/{MAX_EXPR} chars  {len(br.paths)} paths  {status}\n"
                )
                handle.write(br.expression)
                handle.write("\n")

    def load_botrules(self) -> list:
        from .rule import BotRule, rule_number

        by_rule: dict[str, list[str]] = {}
        for item in self.ruled.values():
            if not item.rule:
                continue
            by_rule.setdefault(item.rule, []).append(item.path)
        names = set(self.rules) | set(by_rule)
        result = []
        for name in names:
            meta = self.rules.get(name)
            number = rule_number(name)
            if number <= 0:
                continue
            paths = list(by_rule.get(name, []))
            result.append(BotRule(
                name=name,
                number=number,
                paths=paths,
                created=meta.created if meta else "",
                updated=meta.updated if meta else "",
                frozen=meta.frozen if meta else False,
                prev_md5=meta.md5 if meta else "",
                prefix=meta.prefix if meta else "",
            ))
        result.sort(key=lambda r: r.number)
        return result


def _read_hits(path: str) -> dict[str, Hit]:
    hits: dict[str, Hit] = {}
    if not os.path.isfile(path):
        return hits
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            p = row.get("path") or ""
            if not p:
                continue
            try:
                count = int(row.get("count") or 0)
            except ValueError:
                count = 0
            try:
                status = int(row.get("status") or 0)
            except ValueError:
                status = 0
            hits[p] = Hit(
                path=p,
                count=count,
                first_seen=_parse_dt(row.get("first_seen") or ""),
                last_seen=_parse_dt(row.get("last_seen") or ""),
                status=status,
                sample_ip=row.get("sample_ip") or "",
            )
    return hits


def _read_ruled(path: str) -> dict[str, Ruled]:
    ruled: dict[str, Ruled] = {}
    if not os.path.isfile(path):
        return ruled
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            p = row.get("path") or ""
            if not p:
                continue
            try:
                count = int(row.get("count_when_ruled") or 0)
            except ValueError:
                count = 0
            ruled[p] = Ruled(
                path=p,
                ruled_at=row.get("ruled_at") or "",
                count_when_ruled=count,
                rule=row.get("rule") or "",
            )
    return ruled


def _read_rules(path: str) -> dict[str, RuleMeta]:
    rules: dict[str, RuleMeta] = {}
    if not os.path.isfile(path):
        return rules
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            name = row.get("name") or ""
            if not name:
                continue
            frozen = (row.get("frozen") or "").strip() in ("1", "true", "True", "yes")
            rules[name] = RuleMeta(
                name=name,
                cloudflare_name=row.get("cloudflare_name") or "",
                created=row.get("created") or "",
                updated=row.get("updated") or "",
                md5=row.get("md5") or "",
                frozen=frozen,
                prefix=row.get("prefix") or "",
                chars=int(row.get("chars") or 0) if (row.get("chars") or "").isdigit() else 0,
            )
    return rules


def _read_allow(path: str) -> dict[str, Allowed]:
    allow: dict[str, Allowed] = {}
    if not os.path.isfile(path):
        return allow
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            p = row.get("path") or ""
            if not p:
                continue
            allow[p] = Allowed(path=p, note=row.get("note") or "")
    return allow


def _read_pending(path: str) -> dict[str, None]:
    pending: dict[str, None] = {}
    if not os.path.isfile(path):
        return pending
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            p = row.get("path") or ""
            if p:
                pending[p] = None
    return pending


def _read_preset_flags(path: str) -> dict[str, bool]:
    from .presets import PRESETS, default_enabled

    flags = default_enabled()
    if not os.path.isfile(path):
        return flags
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            name = (row.get("name") or "").strip()
            if name not in PRESETS:
                continue
            raw = (row.get("enabled") or "").strip().lower()
            flags[name] = raw in ("1", "true", "yes", "on")
    return flags


def _read_watermarks(path: str) -> dict[str, FileWatermark]:
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    raw = payload.get("inodes") or {}
    result: dict[str, FileWatermark] = {}
    for ino, data in raw.items():
        result[str(ino)] = FileWatermark(
            path=data.get("path") or "",
            offset=int(data.get("offset") or 0),
            size=int(data.get("size") or 0),
        )
    return result
