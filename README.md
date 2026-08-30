BotFuzz
=======

Scan Apache `access.log` for obvious probe 404s (silly paths that will never
be real URLs), accumulate counts in sorted CSV files, and from time to time
review the top residue, categorize each path as allow or block, then
**emit** paste-ready Cloudflare WAF rules from the latest decisions.

Preset prefixes (on by default)
-------------------------------

Enabled presets are **not** separate Cloudflare rules. They are OR'd onto
the front of **botfuzz-1** so they do not burn a whole 4K slot. They also
collapse whole families (every `.svn` URL, every `.git` URL) to one matcher,
and those hits are not counted in `hits.csv`.

1. **obvious-bad** — always on. `.git`, `.svn`, `.htpasswd`, `.env`, `cgi-bin`,
   GraphQL, Vite/build `manifest.json`, and PHP under `/.well-known/`.
2. **not-wordpress** — on by default. Turn off if the host runs WordPress
   (and turn off **root-php** as well).
3. **root-php** — on by default. Blocks `/*.php` at the document root except
   `index.php`, `about.php`, `contact.php`, and `home.php`. Turn off if you
   serve other PHP files at `/`. The allow list is **not** copied into
   Cloudflare; it only keeps those paths out of residue `in { … }` lists.

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

Then review — every time, ten at a time
---------------------------------------

Presets collapse whole families. What is left in `top` is residue: some of
it is junk to block, and some of it is a real URL that 404'd. Look at a
small batch and categorize **each** path.

    ./botfuzz top --interactive          # default 10; a=allow b=queue-block other=skip
    ./botfuzz emit                       # regenerate Cloudflare paste from latest

`block` / interactive **b** only queues paths (`data/pending.csv`). They are
not in a Cloudflare rule until you **emit**. Emit folds the queue into the
open named rule, refreshes preset prefixes, writes `data/rules/botfuzz-N.txt`,
and prints what to paste. Run emit again anytime to reprint from the latest
ruled paths and presets (no new residue is scooped up).

    ./botfuzz block /about/function.php  # queue
    ./botfuzz block                      # list the queue
    ./botfuzz emit                       # write rules and print paste
    ./botfuzz emit --all                 # reprint every named rule

`./botfuzz rule -n 10 --mark` still works as “take the current top batch
into the rule immediately” if you do not want the queue.

Allowing after a path is already in a frozen Cloudflare rule does not pull
it out. Categorize before you emit when you can.

Named bot rules
---------------

Residue paths go into `botfuzz-1`, `botfuzz-2`, … **botfuzz-1** starts with
the enabled preset expressions, then exact residue paths. Later rules are
residue only.

A named rule **stays open** and grows across **emit** runs until its
Cloudflare expression is about 4k characters. Each emit that adds paths
updates that rule’s date and MD5; update the same Cloudflare rule in the
dashboard (do not create a new one). When it is full it freezes, and the
next emit starts `botfuzz-2`. That keeps you from burning the five free
Cloudflare rules on half-empty expressions.

    ./botfuzz emit                  # from pending + current presets
    ./botfuzz emit --all            # reprint every named rule
    ./botfuzz rule --list           # which rules are open vs frozen
    ./botfuzz rule --show botfuzz-1
    ./botfuzz rule --freeze         # lock the last rule early; next emit starts N+1

Allow list
----------

A 404 can still look like a probe (e.g. `/manifest.json`) but be something
you do not want Cloudflare to block. The allow list lives **only in BotFuzz**
(`data/allow.csv`). `top`, `block`, and `emit` skip those paths so they never
go into a `in { … }` block list. Hundreds of allows do not consume Cloudflare
character budget.

Allowing a path does not pull it out of a frozen bot rule already in
Cloudflare. Allow it before `emit` when you can.

- Exact path: `/manifest.json`
- Prefix: `/app/` (trailing slash) skips every path under that tree

```
path,note
/manifest.json,PWA clients fetch this
/app/,application
```

    ./botfuzz allow /manifest.json --note "PWA clients fetch this"
    ./botfuzz allow /app/ --note "application"
    ./botfuzz allow                 # list

CSV files
---------

All state lives under `data/` (override with `--data DIR`). Commit that
folder when you want the paste-ready rules on GitHub. Wipe it to start
over.

- `hits.csv` — residue probe paths (presets are not counted): path, count, first_seen, last_seen, status, sample_ip
- `presets.csv` — live on/off copy (restored from `presets.sample.csv` after a wipe)
- `allow.csv` — paths (or prefixes ending in `/`) that must never go into a Cloudflare rule: path, note
- `pending.csv` — queued block paths (**gitignored**); folded in by `emit`
- `ruled.csv` — paths already in a generated bot rule: path, ruled_at, count_when_ruled, rule
- `rules.csv` — generated rules: name, cloudflare_name, created, updated, md5, frozen, chars, prefix
- `rules/botfuzz-N.txt` — paste-ready expression for each named rule (updated in place while open)
- `state.json` — per-inode read watermark (**gitignored**, machine-local)

Sharing and reset
-----------------

Run, `emit`, commit `data/`. Others can paste `data/rules/botfuzz-*.txt`
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

400/403/404 on scanner paths (`.git`, `.env`, `wp-admin`, phpmyadmin, …).
PHP files count only on **404** (the script is missing). A **403** on a
real script is the app refusing access (logged-out API poll, CSRF, …),
not a probe. Common page names such as `index.php`, `about.php`,
`contact.php`, and `privacy.php` are never probes (any directory). Names
like `admin.php` and `1.php` still count when they 404. Ordinary 404s on
HTML or other non-PHP paths are ignored. Use the allow list if a real
PHP URL is being miscounted. The Cloudflare **root-php** block only excepts
`index.php` / `about.php` / `contact.php` / `home.php`. Other common names
are ignored in `top` but still blocked at the edge if a scanner requests
them. The allow list is never pasted into Cloudflare.

    ./botfuzz scan --self-test
