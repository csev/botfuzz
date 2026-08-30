"""BotFuzz CLI: scan Apache access logs, list top probes, emit Cloudflare rules."""

from __future__ import annotations

import argparse
import os

from datetime import datetime, timezone

from .csvstore import Allowed, Hit, Store, is_allowed
from .parse import parse_access_line
from .probes import is_probe
from .rule import (
    DEFAULT_PER_RULE,
    assign_new,
    cloudflare_safe,
    print_assignment,
    print_one_rule,
    print_rule_list,
)
from .presets import (
    PRESET_ORDER,
    PRESETS,
    covers_not_wordpress,
    covers_obvious_bad,
    covers_root_php,
    default_enabled,
    preset_prefix,
    print_enabled_presets,
    print_preset,
)
from .scan import resolve_access_files, scan_files


def repo_root() -> str:
    # src/botfuzz/__main__.py -> repo root
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def default_data_dir() -> str:
    return os.path.join(repo_root(), "data")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="botfuzz",
        description="Track silly Apache 404s over time and emit Cloudflare WAF rules.",
    )
    parser.add_argument(
        "--data",
        default=default_data_dir(),
        help="Directory for CSV files (default: ./data in this repo)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Read access logs and merge probe paths into hits.csv")
    scan.add_argument(
        "paths",
        nargs="*",
        help="Log directory (e.g. /tmp/apache2) or a specific access.log",
    )
    scan.add_argument("--dir", "--log-dir", dest="dir", help="Log directory")
    scan.add_argument(
        "--rotated",
        action="store_true",
        help="Also read access.log.1 and *.gz rotations (for a one-time backfill)",
    )
    scan.add_argument("--self-test", action="store_true", help="Run probe checks and exit")

    top = sub.add_parser("top", help="Show the worst unmarked probe paths")
    top.add_argument("-n", "--n", type=int, default=30, help="How many paths (default 30)")

    rule = sub.add_parser(
        "rule",
        help="Assign top unmarked paths to named Cloudflare bot rules (date + MD5)",
    )
    rule.add_argument(
        "-n",
        "--n",
        type=int,
        default=None,
        help="How many new paths to add (default 30; omitted with --freeze so the last rule is locked as-is)",
    )
    rule.add_argument(
        "--per-rule",
        type=int,
        default=DEFAULT_PER_RULE,
        help="Optional extra path-count cap per named rule (default 0: grow until ~4k characters)",
    )
    rule.add_argument(
        "--mark",
        action="store_true",
        help="Record assignments in ruled.csv and rules.csv",
    )
    rule.add_argument(
        "--freeze",
        action="store_true",
        help="Freeze the last rule so the next run starts botfuzz-N+1",
    )
    rule.add_argument("--list", action="store_true", help="List named bot rules and exit")
    rule.add_argument("--show", metavar="NAME", help="Reprint one named rule (e.g. botfuzz-1)")
    rule.add_argument(
        "--all",
        action="store_true",
        help="Reprint every named rule (recovery); skip if MD5 matches Cloudflare",
    )
    rule.add_argument(
        "--presets",
        action="store_true",
        help="Show preset expressions (these are prepended to botfuzz-1, not separate Cloudflare rules)",
    )
    rule.add_argument(
        "--not-wordpress",
        action="store_true",
        help="Print the static not-WordPress preset",
    )
    rule.add_argument(
        "--obvious-bad",
        action="store_true",
        help="Print the static obvious-bad preset (.git, .env, cgi-bin)",
    )

    preset = sub.add_parser("preset", help="Enable or disable paste-ready preset rules")
    preset.add_argument(
        "name",
        nargs="?",
        help="Preset name: obvious-bad, not-wordpress, or root-php",
    )
    preset.add_argument(
        "state",
        nargs="?",
        choices=("on", "off"),
        help="Turn the preset on or off (writes data/presets.csv)",
    )

    allow = sub.add_parser(
        "allow",
        help="Never put a path (or prefix ending in /) into a Cloudflare rule",
    )
    allow.add_argument(
        "path",
        nargs="?",
        help="Exact path, or a prefix ending in / (e.g. /app/ skips everything under it)",
    )
    allow.add_argument("--note", default="", help="Optional reason")
    return parser


def self_test() -> int:
    cases = [
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /.git/config HTTP/1.1" '
            '404 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /wp-admin/setup-config.php HTTP/1.1" '
            '404 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /app/page.html HTTP/1.1" '
            '404 123 "-" "Mozilla/5.0"',
            False,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /index.html HTTP/1.1" '
            '200 123 "-" "Mozilla/5.0"',
            False,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /missing-page HTTP/1.1" '
            '404 123 "-" "Mozilla/5.0"',
            False,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /shell.php HTTP/1.1" '
            '404 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /about.php HTTP/1.1" '
            '404 123 "-" "Mozilla/5.0"',
            False,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /index.php HTTP/1.1" '
            '404 123 "-" "Mozilla/5.0"',
            False,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /blog/index.php HTTP/1.1" '
            '404 123 "-" "Mozilla/5.0"',
            False,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /admin.php HTTP/1.1" '
            '404 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /api/graphql HTTP/1.1" '
            '404 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /about/function.php HTTP/1.1" '
            '404 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] '
            '"GET /app/api/notifications.php HTTP/1.1" 403 123 "-" "Mozilla/5.0"',
            False,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] '
            '"GET /app/api/notifications.php HTTP/1.1" 404 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /.git/config HTTP/1.1" '
            '403 123 "-" "curl/8.0"',
            True,
        ),
        (
            '1.2.3.4 - - [27/Aug/2026:00:00:03 +0000] "GET /shell.php HTTP/1.1" '
            '403 123 "-" "curl/8.0"',
            True,
        ),
    ]
    failed = 0
    for raw, expect in cases:
        event = parse_access_line(raw)
        if event is None:
            print(f"FAIL parse: {raw[:80]}")
            failed += 1
            continue
        got = is_probe(event)
        if got != expect:
            print(f"FAIL expected probe={expect} got {got}")
            print(f"  {raw[:120]}")
            failed += 1
    if failed:
        print(f"{failed} self-test failure(s)")
        return 1
    packed = assign_new([], ["/a", "/b", "/c"], per_rule=2, today="2026-08-30")
    if [r.name for r in packed] != ["botfuzz-1", "botfuzz-2"]:
        print(f"FAIL assign names {[r.name for r in packed]}")
        return 1
    if not packed[0].frozen or packed[1].frozen:
        print("FAIL assign freeze: expected botfuzz-1 frozen, botfuzz-2 open")
        return 1
    if packed[0].md5 == packed[1].md5:
        print("FAIL expected different MD5s")
        return 1
    for rule in packed:
        rule.prev_md5 = rule.md5
    grown = assign_new(packed, ["/d"], per_rule=2, today="2026-08-31")
    if grown[0].changed:
        print("FAIL frozen rule should be unchanged")
        return 1
    if grown[0].md5 != packed[0].md5:
        print("FAIL frozen rule MD5 changed")
        return 1
    if not grown[1].changed or not grown[1].frozen or len(grown[1].paths) != 2:
        print("FAIL expected botfuzz-2 to fill, change, and freeze")
        return 1
    pref = preset_prefix(default_enabled())
    with_preset = assign_new([], ["/shell.php"], per_rule=30, today="2026-08-30", prefix=pref)
    if "/.git" not in with_preset[0].expression or "/shell.php" not in with_preset[0].expression:
        print("FAIL botfuzz-1 should start with presets and include residue paths")
        return 1
    if with_preset[0].number != 1 or "/.svn" in with_preset[0].paths:
        print("FAIL presets must not be stored as exact paths")
        return 1
    growing = assign_new([], ["/a", "/b", "/c"], per_rule=0, today="2026-08-30")
    if len(growing) != 1 or growing[0].frozen:
        print("FAIL without a path cap, one rule should stay open until ~4k")
        return 1
    store = Store("/unused")
    store.hits["/keep"] = Hit(path="/keep", count=2)
    store.hits["/skip"] = Hit(path="/skip", count=9)
    store.allow["/skip"] = Allowed(path="/skip", note="false positive")
    unmarked = [h.path for h in store.unmarked_hits()]
    if unmarked != ["/keep"]:
        print(f"FAIL allow list should hide /skip, got {unmarked}")
        return 1
    store.hits["/app/lib/foo.php"] = Hit(path="/app/lib/foo.php", count=40)
    store.allow["/app/"] = Allowed(path="/app/", note="application")
    unmarked = [h.path for h in store.unmarked_hits()]
    if "/app/lib/foo.php" in unmarked:
        print("FAIL prefix allow /app/ should hide /app/lib/foo.php")
        return 1
    if "/keep" not in unmarked:
        print("FAIL prefix allow should not hide /keep")
        return 1
    if not covers_not_wordpress("/wp-admin/setup-config.php"):
        print("FAIL expected /wp-admin to be not-wordpress")
        return 1
    if not covers_obvious_bad("/.git/config") or not covers_obvious_bad("/cgi-bin/foo"):
        print("FAIL expected /.git and /cgi-bin to be obvious-bad")
        return 1
    if covers_not_wordpress("/shell.php") or covers_not_wordpress("/wrapper.php"):
        print("FAIL did not expect /shell.php or /wrapper.php to be WordPress")
        return 1
    if covers_obvious_bad("/wp-admin/setup-config.php"):
        print("FAIL WordPress paths should not be obvious-bad")
        return 1
    if not covers_obvious_bad("/api/graphql") or not covers_obvious_bad("/.vite/manifest.json"):
        print("FAIL expected graphql and vite manifests to be obvious-bad")
        return 1
    if not covers_not_wordpress("/wp.php"):
        print("FAIL expected /wp.php to be not-wordpress")
        return 1
    if not covers_not_wordpress("/blog/wp/v2/posts"):
        print("FAIL expected /blog/wp/v2/ to be not-wordpress")
        return 1
    if not covers_obvious_bad("/actuator/env"):
        print("FAIL expected /actuator/env to be obvious-bad")
        return 1
    if not covers_root_php("/1.php") or not covers_root_php("/goat.php") or not covers_root_php("/ioxi002.PhP7"):
        print("FAIL expected lonely PHP to be root-php")
        return 1
    if covers_root_php("/about.php") or covers_root_php("/index.php"):
        print("FAIL brochure pages must not be root-php")
        return 1
    if covers_root_php("/about/function.php") or covers_root_php("/blog/post.php"):
        print("FAIL nested PHP must not be root-php")
        return 1
    store.hits["/wp-login.php"] = Hit(path="/wp-login.php", count=99)
    store.hits["/wp-admin/setup-config.php"] = Hit(path="/wp-admin/setup-config.php", count=50)
    unmarked = [h.path for h in store.unmarked_hits()]
    if "/wp-login.php" in unmarked or "/wp-admin/setup-config.php" in unmarked:
        print("FAIL WordPress paths should not go into generated rules")
        return 1
    store.preset_flags = {"obvious-bad": True, "not-wordpress": False, "root-php": True}
    unmarked = [h.path for h in store.unmarked_hits()]
    if "/wp-login.php" in unmarked:
        print("FAIL root-php should still hide /wp-login.php when not-wordpress is off")
        return 1
    if "/wp-admin/setup-config.php" not in unmarked:
        print("FAIL disabling not-wordpress should surface nested /wp-admin paths")
        return 1
    store.hits["/1.php"] = Hit(path="/1.php", count=20)
    store.hits["/about/function.php"] = Hit(path="/about/function.php", count=12)
    store.preset_flags = {"obvious-bad": True, "not-wordpress": True, "root-php": True}
    unmarked = [h.path for h in store.unmarked_hits()]
    if "/1.php" in unmarked:
        print("FAIL root-php should hide /1.php")
        return 1
    if "/about/function.php" not in unmarked:
        print("FAIL nested PHP should still be residue")
        return 1
    store.hits["/app/api/notifications.php"] = Hit(
        path="/app/api/notifications.php", count=4400, status=403
    )
    unmarked = [h.path for h in store.unmarked_hits()]
    if "/app/api/notifications.php" in unmarked:
        print("FAIL 403 on a real PHP script should not be residue")
        return 1
    print("self-test ok")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if args.self_test:
        return self_test()
    store = Store(args.data)
    store.load()
    files = resolve_access_files(args.paths, args.dir, args.rotated)
    stats = scan_files(store, files)
    print(f"Scanned {stats.files} file(s), skipped {stats.skipped_files} already-read")
    print(f"  {stats.lines} lines, {stats.parsed} parsed, {stats.probes} probes")
    if stats.preset_probes:
        print(f"  {stats.preset_probes} collapsed by presets (not counted in hits.csv)")
    print(f"  {stats.new_paths} new paths, {len(store.hits)} total in {store.hits_path}")
    print("Next: ./botfuzz top -n 30")
    print("Allow anything that must not be blocked, then top -n 30 again.")
    print("When the list is all junk: ./botfuzz rule -n 30 --mark")
    return 0


def cmd_top(args: argparse.Namespace) -> int:
    store = Store(args.data)
    store.load()
    hits = store.top_unmarked(args.n)
    if not hits:
        print("No unmarked probe paths in hits.csv")
        return 0
    width = max(len(str(h.count)) for h in hits)
    print(f"{'count':>{width}}  path")
    for hit in hits:
        print(f"{hit.count:>{width}}  {hit.path}")
    remaining = len(store.unmarked_hits()) - len(hits)
    if remaining > 0:
        print(f"... {remaining} more unmarked paths")
    allowed = [h for h in store.hits.values() if is_allowed(h.path, store.allow)]
    if allowed:
        print(
            f"({len(allowed)} path(s) omitted — allow list, "
            f"{len(store.allow)} exact/prefix rule(s))"
        )
    covered = store.preset_hits()
    if covered:
        on = [n for n in PRESET_ORDER if store.enabled_presets().get(n)]
        print(
            f"({len(covered)} path(s) omitted — covered by presets: {', '.join(on)})"
        )
    print(
        f"Allow false positives: ./botfuzz allow /path --note \"...\""
    )
    print(f"Then: ./botfuzz top -n {args.n}   (again, until this list is all junk)")
    print(f"Then: ./botfuzz rule -n {args.n} --mark")
    return 0


def cmd_rule(args: argparse.Namespace) -> int:
    if args.presets:
        store = Store(args.data)
        store.load()
        print_enabled_presets(store.enabled_presets())
        return 0
    if args.not_wordpress:
        print_preset(PRESETS["not-wordpress"])
        return 0
    if args.obvious_bad:
        print_preset(PRESETS["obvious-bad"])
        return 0
    store = Store(args.data)
    store.load()
    existing = store.load_botrules()

    if args.list:
        print_rule_list(existing)
        return 0
    if args.show:
        found = next((r for r in existing if r.name == args.show), None)
        if found is None:
            print(f"No rule named {args.show}")
            return 1
        print_one_rule(found, paste=True)
        return 0
    if args.all:
        if not existing:
            print("No named bot rules yet. Run: ./botfuzz rule -n 30 --mark")
            return 0
        print_assignment(existing, [], show_all=True)
        return 0

    freeze_only = bool(args.freeze and args.n is None)
    if freeze_only:
        usable: list[str] = []
        skipped: list[str] = []
    else:
        n = 30 if args.n is None else args.n
        hits = store.top_unmarked(n)
        paths = [h.path for h in hits]
        usable = [p for p in paths if cloudflare_safe(p)]
        skipped = [p for p in paths if not cloudflare_safe(p)]
    today = datetime.now(timezone.utc).date().isoformat()
    prefix = preset_prefix(store.enabled_presets())

    if not usable and not args.freeze and not existing and not prefix:
        print("No unmarked probe paths in hits.csv")
        return 0
    if not usable and not args.freeze and existing and not prefix:
        print_assignment(existing, skipped)
        return 0

    updated = assign_new(
        existing,
        usable,
        per_rule=args.per_rule,
        today=today,
        freeze_last=args.freeze,
        prefix=prefix,
    )
    print_assignment(updated, skipped)
    if args.mark or args.freeze:
        added = store.sync_botrules(updated)
        store.save_ruled()
        store.save_rules()
        print(f"# saved {added} new path(s); rules in {store.rules_path}")
    elif any(r.changed for r in updated):
        print(
            "# preview only — if any path should not be blocked, allow it, "
            "run top again, then --mark"
        )
    return 0


def cmd_preset(args: argparse.Namespace) -> int:
    store = Store(args.data)
    store.load()
    if not args.name:
        flags = store.enabled_presets()
        print(f"{'name':<16} {'on':<4}  md5")
        for name in PRESET_ORDER:
            preset = PRESETS[name]
            on = "yes" if flags.get(name) else "no"
            print(f"{name:<16} {on:<4}  {preset.md5}")
            print(f"                 {preset.recommended}")
        print(f"Config: {store.presets_path}")
        print("Enabled presets are prepended to botfuzz-1 (not pasted as their own rules)")
        return 0
    if args.name not in PRESETS:
        print(f"Unknown preset {args.name}. Choose: {', '.join(PRESET_ORDER)}")
        return 1
    if not args.state:
        print_preset(PRESETS[args.name])
        flags = store.enabled_presets()
        print(f"# enabled in config: {'yes' if flags.get(args.name) else 'no'}")
        return 0
    enabled = args.state == "on"
    if args.name == "obvious-bad" and not enabled:
        print("warning: obvious-bad is recommended for every host")
    store.set_preset(args.name, enabled)
    store.save_presets()
    print(f"{args.name} {'on' if enabled else 'off'} in {store.presets_path}")
    return 0


def cmd_allow(args: argparse.Namespace) -> int:
    store = Store(args.data)
    store.load()
    if not args.path:
        if not store.allow:
            print("Allow list is empty. Add a path or edit data/allow.csv:")
            print("path,note")
            print("/manifest.json,PWA clients fetch this")
            print("/app/,application tree (trailing slash = prefix)")
            return 0
        width = max(len(a.path) for a in store.allow.values())
        print(f"{'path':<{width}}  note")
        for item in sorted(store.allow.values(), key=lambda a: a.path):
            kind = "prefix" if item.path.endswith("/") else "exact"
            print(f"{item.path:<{width}}  {item.note or kind}")
        return 0
    path = args.path
    if not path.startswith("/"):
        path = "/" + path
    already_ruled = store.ruled.get(path)
    added = store.add_allow(path, args.note)
    store.save_allow()
    kind = "prefix" if path.endswith("/") else "path"
    if added:
        print(f"Allowed {kind} {path} in {store.allow_path}")
    else:
        print(f"Updated {kind} {path} in {store.allow_path}")
    if path.endswith("/"):
        print("Trailing slash: every path under this prefix is omitted from top/rule")
    if already_ruled:
        print(
            f"warning: this path is already in {already_ruled.rule}; "
            "frozen Cloudflare rules are not rewritten. "
            "Allow list only prevents new assignments."
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "top":
        return cmd_top(args)
    if args.cmd == "rule":
        return cmd_rule(args)
    if args.cmd == "preset":
        return cmd_preset(args)
    if args.cmd == "allow":
        return cmd_allow(args)
    build_parser().error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
