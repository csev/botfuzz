"""Named Cloudflare WAF bot rules: identity, date, MD5, freeze-when-full."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

MAX_EXPR = 3800
DEFAULT_PER_RULE = 0  # 0 = no path-count cap; freeze only when the expression is ~4k
RULE_NAME_RE = re.compile(r"^botfuzz-(\d+)$")


def cloudflare_safe(path: str) -> bool:
    if not path or path[0] != "/":
        return False
    if '"' in path or "\\" in path or "\n" in path or "\r" in path:
        return False
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in path):
        return False
    if len(path) > 512:
        return False
    return True


def _quote(path: str) -> str:
    return '"' + path + '"'


def format_expression(paths: list[str]) -> str:
    inner = " ".join(_quote(p) for p in sorted(paths))
    return f"(http.request.uri.path in {{{inner}}})"


def format_rule_expression(paths: list[str], prefix: str = "") -> str:
    parts = []
    if prefix:
        parts.append(prefix)
    if paths:
        parts.append(format_expression(paths))
    return " or\n".join(parts)


def path_md5(paths: list[str], prefix: str = "") -> str:
    canonical = prefix + "\n" + "\n".join(sorted(paths))
    if not canonical.strip():
        return ""
    return hashlib.md5(canonical.encode("utf-8")).hexdigest()[:12]


def rule_name(number: int) -> str:
    return f"botfuzz-{number}"


def rule_number(name: str) -> int:
    match = RULE_NAME_RE.match(name)
    return int(match.group(1)) if match else 0


def cloudflare_rule_name(number: int, date: str, md5: str) -> str:
    """Dashboard name: stable identity + paste date + content fingerprint."""
    return f"BotFuzz-{number} {date} {md5}"


@dataclass
class BotRule:
    name: str
    number: int
    paths: list[str] = field(default_factory=list)
    created: str = ""
    updated: str = ""
    frozen: bool = False
    prev_md5: str = ""
    prefix: str = ""

    @property
    def md5(self) -> str:
        return path_md5(self.paths, self.prefix)

    @property
    def expression(self) -> str:
        return format_rule_expression(self.paths, self.prefix)

    @property
    def chars(self) -> int:
        return len(self.expression)

    @property
    def cloudflare_name(self) -> str:
        return cloudflare_rule_name(self.number, self.updated, self.md5)

    @property
    def changed(self) -> bool:
        return self.md5 != self.prev_md5

    def can_add(self, path: str, per_rule: int) -> bool:
        if self.frozen:
            return False
        if per_rule > 0 and len(self.paths) >= per_rule:
            return False
        trial = format_rule_expression(self.paths + [path], self.prefix)
        return len(trial) <= MAX_EXPR

    def add(self, path: str, today: str) -> None:
        if path not in self.paths:
            self.paths.append(path)
        self.updated = today
        if not self.created:
            self.created = today

    def mark_full(self, per_rule: int) -> None:
        if per_rule > 0 and self.paths and len(self.paths) >= per_rule:
            self.frozen = True
            return
        if self.expression and len(self.expression) >= MAX_EXPR:
            self.frozen = True


def copy_rules(rules: list[BotRule]) -> list[BotRule]:
    return [
        BotRule(
            name=r.name,
            number=r.number,
            paths=list(r.paths),
            created=r.created,
            updated=r.updated,
            frozen=r.frozen,
            prev_md5=r.prev_md5,
            prefix=r.prefix,
        )
        for r in rules
    ]


def _new_rule(rules: list[BotRule], today: str, prefix: str = "") -> BotRule:
    number = rules[-1].number + 1 if rules else 1
    created = BotRule(
        name=rule_name(number),
        number=number,
        created=today,
        updated=today,
        frozen=False,
        prev_md5="",
        prefix=prefix if number == 1 else "",
    )
    rules.append(created)
    return created


def _open_rule(rules: list[BotRule], today: str, prefix: str = "") -> BotRule:
    if rules and not rules[-1].frozen:
        return rules[-1]
    return _new_rule(rules, today, prefix=prefix)


def assign_new(
    rules: list[BotRule],
    new_paths: list[str],
    per_rule: int,
    today: str,
    freeze_last: bool = False,
    prefix: str = "",
) -> list[BotRule]:
    """Add new paths to the last open rule; start a new named rule when full.

    Frozen rules are never modified. Preset expressions go on botfuzz-1 only.
    Returns a new list (does not mutate input).
    """
    out = copy_rules(rules)
    if prefix and out and out[0].number == 1 and not out[0].frozen:
        if out[0].prefix != prefix:
            out[0].prefix = prefix
            out[0].updated = today
    for path in new_paths:
        current = _open_rule(out, today, prefix=prefix)
        if not current.can_add(path, per_rule):
            current.frozen = True
            current = _new_rule(out, today, prefix=prefix)
        current.add(path, today)
        current.mark_full(per_rule)
    if prefix and not any(r.number == 1 for r in out):
        starter = BotRule(
            name=rule_name(1),
            number=1,
            created=today,
            updated=today,
            prefix=prefix,
        )
        out.insert(0, starter)
    if freeze_last and out:
        out[-1].frozen = True
    return out


def print_rule_list(rules: list[BotRule]) -> None:
    if not rules:
        print("No named bot rules yet. Run: ./botfuzz rule -n 30 --mark")
        return
    print(
        f"{'name':<12} {'status':<8} {'date':<12} {'md5':<12} "
        f"{'chars':>10} {'paths':>5}  cloudflare name"
    )
    for rule in rules:
        status = "frozen" if rule.frozen else "open"
        size = f"{rule.chars}/{MAX_EXPR}"
        print(
            f"{rule.name:<12} {status:<8} {rule.updated:<12} {rule.md5:<12} "
            f"{size:>10} {len(rule.paths):>5}  {rule.cloudflare_name}"
        )


def print_one_rule(rule: BotRule, *, paste: bool) -> None:
    status = "FROZEN" if rule.frozen else "OPEN"
    if paste and rule.frozen:
        action = "Paste this Cloudflare custom WAF rule (action: Block), then leave it"
    elif paste and not rule.prev_md5:
        action = "Paste this as a new Cloudflare custom WAF rule (action: Block)"
    elif paste:
        action = (
            "Update the existing Cloudflare rule (same botfuzz-N, new date+MD5). "
            "It is not full yet — later runs will keep growing it"
        )
    else:
        action = "Already in Cloudflare — skip"
    print(f"# {action}")
    print(f"# Cloudflare rule name: {rule.cloudflare_name}")
    print(
        f"# Identity: {rule.name}  md5={rule.md5}  "
        f"{len(rule.paths)} paths  {rule.chars}/{MAX_EXPR} chars  "
        f"{status}  updated {rule.updated}"
    )
    if rule.prefix:
        print("# Starts with enabled presets (collapsed .git/.svn/.env/WordPress/…)")
    expr = rule.expression
    if not expr:
        print("# (empty)")
        return
    print(expr)


def print_assignment(
    rules: list[BotRule],
    skipped: list[str],
    *,
    show_all: bool = False,
) -> None:
    if skipped:
        print(f"# skipped {len(skipped)} path(s) with quotes or non-ASCII:")
        for path in skipped:
            print(f"#   {path}")
        print()
    unchanged = [r for r in rules if not r.changed and (r.paths or r.prefix)]
    changed = [r for r in rules if r.changed and (r.paths or r.prefix)]
    if unchanged and not show_all:
        print("# Unchanged (leave these alone in Cloudflare):")
        for rule in unchanged:
            status = "frozen" if rule.frozen else "open"
            print(
                f"#   {rule.name}  {rule.cloudflare_name}  "
                f"{len(rule.paths)} paths  {rule.chars}/{MAX_EXPR} chars  {status}"
            )
        print()
    to_print = rules if show_all else changed
    if not to_print:
        print("# Nothing new to paste. Last rule MD5 is unchanged.")
        return
    for i, rule in enumerate(to_print):
        if i:
            print()
        print_one_rule(rule, paste=rule.changed or show_all)
