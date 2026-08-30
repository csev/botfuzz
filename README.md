BotFuzz
=======

Scan Apache `access.log` for obvious probe 404s (silly paths that will never
be real URLs), accumulate counts in sorted CSV files, and from time to time
turn the worst offenders into named Cloudflare WAF rules.

Preset prefixes (on by default)
-------------------------------

Enabled presets are **not** separate Cloudflare rules. They are OR'd onto
the front of **botfuzz-1** so they do not burn a whole 4K slot. They also
collapse whole families (every `.svn` URL, every `.git` URL) to one matcher,
and those hits are not counted in `hits.csv`.

1. **obvious-bad** — always on. `.git`, `.svn`, `.htpasswd`, `.env`, `cgi-bin`.
2. **not-wordpress** — on by default. Turn off if the host runs WordPress.

    ./botfuzz preset                     # on/off (writes data/presets.csv)
    ./botfuzz preset not-wordpress off
    ./botfuzz rule --presets             # show the expressions (for inspection)

Lasting defaults live in `presets.sample.csv` at the repo root (survives
`rm -rf data`). After a reset, that sample is copied to `data/presets.csv`.
Edit the sample if you want every fresh start to keep `not-wordpress` off.

Daily
-----

    ./botfuzz scan /var/log/apache2

That merges new probes into `data/hits.csv` and remembers how far it read
(`data/state.json`) so a second run the same day does not double-count.

One-time backfill of rotated logs:

    ./botfuzz scan --rotated /var/log/apache2

Named bot rules
---------------

Residue paths go into `botfuzz-1`, `botfuzz-2`, … **botfuzz-1** starts with
the enabled preset expressions, then exact residue paths. Later rules are
residue only.

A named rule **stays open** and grows across runs until its Cloudflare
expression is about 4k characters. Each `--mark` that adds paths updates
that rule’s date and MD5; update the same Cloudflare rule in the dashboard
(do not create a new one). When it is full it freezes, and the next run
starts `botfuzz-2`. That keeps you from burning the five free Cloudflare
rules on half-empty expressions.

    ./botfuzz top -n 30
    ./botfuzz rule -n 30            # preview; shows chars/3800
    ./botfuzz rule -n 30 --mark     # grow the open rule, print what to paste
    ./botfuzz rule --list           # which rules are open vs frozen

    ./botfuzz rule --show botfuzz-1
    ./botfuzz rule --all            # reprint every generated rule (recovery)
    ./botfuzz rule --freeze         # lock the last rule early; next run starts N+1

`--mark` writes `data/ruled.csv`, `data/rules.csv`, and
`data/rules/botfuzz-N.txt` (the paste-ready expression, overwritten as the
open rule grows). Only rules whose MD5 changed are printed to paste.

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

All state lives under `data/` (override with `--data DIR`). Commit that
folder when you want the paste-ready rules on GitHub. Wipe it to start
over.

- `hits.csv` — residue probe paths (presets are not counted): path, count, first_seen, last_seen, status, sample_ip
- `presets.csv` — live on/off copy (restored from `presets.sample.csv` after a wipe)
- `allow.csv` — paths that must never go into a Cloudflare rule: path, note
- `ruled.csv` — paths already in a generated bot rule: path, ruled_at, count_when_ruled, rule
- `rules.csv` — generated rules: name, cloudflare_name, created, updated, md5, frozen, chars, prefix
- `rules/botfuzz-N.txt` — paste-ready expression for each named rule (updated in place while open)
- `state.json` — per-inode read watermark (**gitignored**, machine-local)

Sharing and reset
-----------------

Run, `--mark`, commit `data/`. Others can paste `data/rules/botfuzz-*.txt`
if they use the same presets (not WordPress, obvious-bad on).

If they **are** WordPress, or they do not want your accumulated residue
paths, they delete `data/` and start fresh:

    rm -rf data

Preset on/off defaults survive that wipe: they live in `presets.sample.csv`
at the repo root and are copied into `data/presets.csv` on the next run.
Edit the sample (e.g. `not-wordpress,0`) if you want every reset to keep
WordPress blocking off. Then scan their own logs and grow their own botfuzz-1.


What counts as a probe
----------------------

Same idea as the Tsugi Apache scanner: 400/403/404 on paths like `.git`,
`.env`, `wp-admin`, phpmyadmin, lonely `/*.php`, and similar junk. Ordinary
404s (a mistyped real page) are ignored.

    ./botfuzz scan --self-test
