BotFuzz
=======

Scan Apache `access.log` for obvious probe 404s (silly paths that will never
be real URLs), accumulate counts in sorted CSV files, and from time to time
turn the worst offenders into named Cloudflare WAF rules.

Daily
-----

    ./botfuzz scan /var/log/apache2

That merges new probes into `data/hits.csv` and remembers how far it read
(`data/state.json`) so a second run the same day does not double-count.

One-time backfill of rotated logs:

    ./botfuzz scan --rotated /var/log/apache2

Named bot rules
---------------

Rules are named `botfuzz-1`, `botfuzz-2`, … and freeze when they fill
(default 30 paths, or when the Cloudflare expression hits ~4k characters).
Frozen rules keep a stable path set and MD5, so you do not re-paste them.
New paths go into the last **open** rule only.

Each Cloudflare rule name is `BotFuzz-N YYYY-MM-DD <md5>` so you can see
whether the dashboard copy still matches local files.

    ./botfuzz top -n 30
    ./botfuzz rule -n 30            # preview
    ./botfuzz rule -n 30 --mark     # assign and print what to paste

    ./botfuzz rule --list
    ./botfuzz rule --show botfuzz-1
    ./botfuzz rule --all            # reprint every rule (recovery)
    ./botfuzz rule --freeze         # lock the last rule; next run starts N+1

`--mark` writes `data/ruled.csv` (path → which rule) and `data/rules.csv`
(name, date, MD5, frozen). Only rules whose MD5 changed are printed to paste.
If `botfuzz-1` and `botfuzz-2` are frozen, a later run only asks you to
create or update `botfuzz-3`.

Allow list
----------

A 404 can still look like a probe (e.g. `/manifest.json`) but be something
you do not want Cloudflare to block. Exact paths in `data/allow.csv` stay
in `hits.csv` so you can see them, but `top` and `rule` skip them.

```
path,note
/manifest.json,PWA clients fetch this
```

    ./botfuzz allow /manifest.json --note "PWA clients fetch this"
    ./botfuzz allow                 # list

Allowing a path does not pull it out of a frozen bot rule already in
Cloudflare. Add it to the allow list before `--mark` when you can.

CSV files
---------

All under `data/` (override with `--data DIR`):

- `hits.csv` — every probe path, sorted: path, count, first_seen, last_seen, status, sample_ip
- `allow.csv` — paths that must never go into a Cloudflare rule: path, note
- `ruled.csv` — paths already in a bot rule: path, ruled_at, count_when_ruled, rule
- `rules.csv` — named rules: name, cloudflare_name, created, updated, md5, frozen
- `state.json` — per-inode read watermark

What counts as a probe
----------------------

Same idea as the Tsugi Apache scanner: 400/403/404 on paths like `.git`,
`.env`, `wp-admin`, phpmyadmin, lonely `/*.php`, and similar junk. Ordinary
404s (a mistyped real page) are ignored.

    ./botfuzz scan --self-test
