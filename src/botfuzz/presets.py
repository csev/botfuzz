"""Paste-ready preset Cloudflare rules, OR'd onto the front of botfuzz-1."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable

from .probes import is_legit_path, is_root_php

OBVIOUS_BAD_EXPRESSION = """\
(http.request.uri.path contains "/.git") or
(http.request.uri.path contains "/.svn") or
(http.request.uri.path contains "/.htpasswd") or
(http.request.uri.path contains "/.env") or
(http.request.uri.path contains "/cgi-bin") or
(http.request.uri.path contains "/graphql") or
(http.request.uri.path contains "/actuator") or
(http.request.uri.path contains ".vite/manifest.json") or
(http.request.uri.path in {"/build/manifest.json" "/dist/manifest.json"}) or
(http.request.uri.path contains "/.well-known/" and lower(http.request.uri.path) contains ".php")"""

NOT_WORDPRESS_EXPRESSION = """\
(starts_with(http.request.uri.path, "/wp-")) or
(starts_with(http.request.uri.path, "/wp/")) or
(http.request.uri.path in {"/wp" "/wp.php" "/wordpress" "/wordpress/"}) or
(http.request.uri.path contains "/wp-admin") or
(http.request.uri.path contains "/wp-login") or
(http.request.uri.path contains "/wp-content") or
(http.request.uri.path contains "/wp-includes") or
(http.request.uri.path contains "/wp-json") or
(http.request.uri.path contains "/wp-config") or
(http.request.uri.path contains "/wp/") or
(http.request.uri.path contains "xmlrpc.php") or
(http.request.uri.path contains "/wordpress/")"""

# Cloudflare `matches` is RE2; keep this under their ~64-char regex budget.
_ROOT_PHP_RE = r"^/[^/]+\.(php[0-9]?|phtml|phar)$"

# Only pages a host commonly serves at /. Not the full probe-ignore list.
ROOT_PHP_KEEP = frozenset({
    "index.php",
    "home.php",
    "about.php",
    "contact.php",
})


def root_php_expression() -> str:
    inner = " ".join(f'"/{name}"' for name in sorted(ROOT_PHP_KEEP))
    return (
        f'(lower(http.request.uri.path) matches "{_ROOT_PHP_RE}") and not '
        f"(lower(http.request.uri.path) in {{{inner}}})"
    )


ROOT_PHP_EXPRESSION = root_php_expression()

_OBVIOUS_CONTAINS = ("/.git", "/.svn", "/.htpasswd", "/.env", "/cgi-bin")
_WP_EXACT = {"/wp", "/wp.php", "/wordpress", "/wordpress/"}
_WP_STARTS = ("/wp-", "/wp/")
_WP_CONTAINS = (
    "/wp-admin",
    "/wp-login",
    "/wp-content",
    "/wp-includes",
    "/wp-json",
    "/wp-config",
    "/wp/",
    "xmlrpc.php",
    "/wordpress/",
)


def _ci(path: str, pred: Callable[[str], bool]) -> bool:
    return pred(path) or pred(path.lower())


def covers_obvious_bad(path: str) -> bool:
    if not path:
        return False
    lowered = path.lower()
    if any(n in path or n in lowered for n in _OBVIOUS_CONTAINS):
        return True
    if "graphql" in lowered:
        return True
    if "/actuator" in lowered:
        return True
    if ".vite/manifest.json" in lowered:
        return True
    if lowered in ("/build/manifest.json", "/dist/manifest.json"):
        return True
    if "/.well-known/" in lowered and ".php" in lowered:
        return True
    return False


def covers_not_wordpress(path: str) -> bool:
    if not path:
        return False

    def pred(p: str) -> bool:
        if p in _WP_EXACT or p.startswith(_WP_STARTS):
            return True
        return any(n in p for n in _WP_CONTAINS)

    return _ci(path, pred)


def covers_root_php(path: str) -> bool:
    if not path or is_legit_path(path):
        return False
    return is_root_php(path)


@dataclass(frozen=True)
class Preset:
    name: str
    label: str
    expression: str
    default_enabled: bool
    recommended: str
    covers: Callable[[str], bool]

    @property
    def md5(self) -> str:
        return hashlib.md5(self.expression.encode("utf-8")).hexdigest()[:12]

    @property
    def cloudflare_name(self) -> str:
        return f"BotFuzz {self.name} {self.md5}"


PRESETS: dict[str, Preset] = {
    "obvious-bad": Preset(
        name="obvious-bad",
        label="Obvious bad stuff (.git, .svn, .env, graphql, vite manifests, …)",
        expression=OBVIOUS_BAD_EXPRESSION,
        default_enabled=True,
        recommended="Leave this on. Nobody should serve .git, GraphQL, or leaked Vite manifests.",
        covers=covers_obvious_bad,
    ),
    "not-wordpress": Preset(
        name="not-wordpress",
        label="I am not WordPress",
        expression=NOT_WORDPRESS_EXPRESSION,
        default_enabled=True,
        recommended="Turn this off if the host actually runs WordPress (also turn off root-php).",
        covers=covers_not_wordpress,
    ),
    "root-php": Preset(
        name="root-php",
        label="No PHP at the document root except index.php / about.php / contact.php / home.php",
        expression=ROOT_PHP_EXPRESSION,
        default_enabled=True,
        recommended=(
            "Blocks /foo.php at document root except index.php, about.php, "
            "contact.php, and home.php. Allow-listed paths stay out of residue "
            "rules; they are not copied into Cloudflare. Turn off if you serve "
            "other PHP at /."
        ),
        covers=covers_root_php,
    ),
}

PRESET_ORDER = ("obvious-bad", "not-wordpress", "root-php")


def default_enabled() -> dict[str, bool]:
    return {name: PRESETS[name].default_enabled for name in PRESET_ORDER}


def covers_path(path: str, enabled: dict[str, bool]) -> bool:
    for name in PRESET_ORDER:
        if enabled.get(name) and PRESETS[name].covers(path):
            return True
    return False


def preset_prefix(enabled: dict[str, bool]) -> str:
    """Enabled preset expressions, wrapped, to OR into botfuzz-1."""
    chunks = []
    for name in PRESET_ORDER:
        if enabled.get(name):
            chunks.append(f"({PRESETS[name].expression})")
    return " or\n".join(chunks)


def print_preset(preset: Preset) -> None:
    print("# This expression is prepended to botfuzz-1 (not a separate Cloudflare rule)")
    print(f"# Preset: {preset.name} — {preset.label}")
    print(f"# {preset.recommended}")
    print(f"# md5={preset.md5}")
    print(preset.expression)


def print_enabled_presets(enabled: dict[str, bool]) -> None:
    to_print = [PRESETS[name] for name in PRESET_ORDER if enabled.get(name)]
    if not to_print:
        print("# No presets enabled. Edit data/presets.csv or: ./botfuzz preset")
        return
    for i, preset in enumerate(to_print):
        if i:
            print()
        print_preset(preset)
