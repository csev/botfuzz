data/
====

This folder **is** BotFuzz's scan/rule memory: hits, allow list, named
Cloudflare rules, and paste-ready expressions.

Preset on/off defaults are **not** only here. Lasting defaults live in
`../presets.sample.csv`. Wiping this folder does not remove that sample;
the next run copies it back to `presets.csv`.

Commit it
---------

Scan, `--mark`, then commit `data/` so the paste-ready rules travel with
the repo. Someone with a similar site (same presets) can copy
`rules/botfuzz-N.txt` into Cloudflare as-is.

Reset
-----

    rm -rf data

Hits, rules, and allow list are gone. Preset defaults come back from
`presets.sample.csv`. `state.json` is gitignored (local log watermarks).
