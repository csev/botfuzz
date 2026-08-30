"""Silly URL patterns that are almost never legitimate on a real site."""

from __future__ import annotations

import re

from .parse import Event

# Scanner / leak path fragments (secrets, CMS probes, debug endpoints).
ACCESS_PROBE_PATH = re.compile(
    r"(?i)("
    r"\.env|\.git|wp-admin|wp-login|wp-content|wp-includes|wp-json|"
    r"/wp(/|$)|wordpress|xmlrpc|phpmyadmin|adminer|autoload_classmap|phpunit|"
    r"cgi-bin|actuator|server-status|\.htpasswd|\.htaccess|"
    r"vendor/|\.aws|secrets\.yml|wp-config|"
    r"eval-stdin|thinkphp|proc/self|etc/passwd|"
    r"debug/default|telescope|_profiler|phpinfo|"
    r"shell\.php|filemanager|graphql|manifest\.json|"
    r"rclone\.conf|service-account\.json|livewire/|"
    r"%2eenv|%2e%2e|\.\./|"
    r"secrets\.json|credentials\.json|serviceAccountKey|service_account|"
    r"config\.json|key\.json|\.ssh/|id_rsa|id_ed25519|id_ecdsa|"
    r"Dockerfile|terraform\.tfstate|firebase-adminsdk"
    r")"
)

PHP_EXT = re.compile(r"\.(?:php[0-9]?|phtml|phar)$", re.I)

# Silly/scanner URLs: 403 is still a probe (.git forbidden, WAF, etc.).
SCANNER_STATUS = (400, 403, 404)
# Other PHP: only a missing file. 403 means the script exists and refused access.
MISSING_STATUS = (404,)

# Common real pages (basename match, any directory). Not admin.php / *.php junk.
LEGIT_BASENAMES = frozenset({
    "index.php",
    "home.php",
    "about.php",
    "about-us.php",
    "aboutus.php",
    "contact.php",
    "contact-us.php",
    "contactus.php",
    "search.php",
    "privacy.php",
    "privacy-policy.php",
    "privacypolicy.php",
    "terms.php",
    "terms-of-service.php",
    "termsofservice.php",
    "tos.php",
    "faq.php",
    "help.php",
    "support.php",
    "news.php",
    "blog.php",
    "articles.php",
    "events.php",
    "calendar.php",
    "gallery.php",
    "photos.php",
    "team.php",
    "staff.php",
    "people.php",
    "faculty.php",
    "courses.php",
    "impressum.php",
    "imprint.php",
    "credits.php",
    "license.php",
    "sitemap.php",
    "rss.php",
    "feed.php",
    "subscribe.php",
    "unsubscribe.php",
    "newsletter.php",
    "donate.php",
    "jobs.php",
    "careers.php",
    "press.php",
    "links.php",
    "resources.php",
})


def is_legit_path(path: str) -> bool:
    if not path or path == "-":
        return False
    base = path.rsplit("/", 1)[-1].split("?")[0].lower()
    return base in LEGIT_BASENAMES


def is_scanner_path(path: str) -> bool:
    if not path or path == "-":
        return False
    if ACCESS_PROBE_PATH.search(path):
        return True
    return path.startswith("/.")


def is_probe_path(path: str, status: int) -> bool:
    """True if this path+status pair is a scanner hit, not a real app response."""
    if not path or path == "-":
        return False
    if is_legit_path(path):
        return False
    if is_scanner_path(path):
        return status in SCANNER_STATUS
    if PHP_EXT.search(path):
        return status in MISSING_STATUS
    return False


def is_probe(event: Event) -> bool:
    """True if this access event is a scanner path worth tracking."""
    if event.garbage:
        return False
    return is_probe_path(event.path or "", event.status)
