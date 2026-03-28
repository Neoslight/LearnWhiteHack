"""Extraction d'adresses email depuis le contenu HTML/RSS d'un site."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.email_harvester")

_RE_EMAIL = re.compile(r"[\w.\-+]+@[\w.\-]+\.\w{2,}", re.IGNORECASE)
_RE_MAILTO = re.compile(r'mailto:([\w.\-+]+@[\w.\-]+\.\w{2,})', re.IGNORECASE)

_CRAWL_PATHS = [
    "/",
    "/contact",
    "/contact-us",
    "/about",
    "/about-us",
    "/a-propos",
    "/nous-contacter",
    "/feed/",
    "/feed/podcast/",
    "/sitemap.xml",
    "/wp-json/wp/v2/users",
    "/.well-known/security.txt",
    "/security.txt",
    "/humans.txt",
]


def run(cfg: AppConfig, report: Report) -> set[str]:
    """Récolte les adresses email exposées sur le site."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return set()

    log.info(f"[bold]recon.email_harvester[/] → {base_url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    all_emails: set[str] = set()
    domain = urlparse(base_url).hostname or ""

    for path in _CRAWL_PATHS:
        url = base_url + path
        try:
            resp = session.get(url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code != 200:
            continue

        # Mailto links
        mailto_emails = set(_RE_MAILTO.findall(resp.text))
        # Regex générale (plus de faux positifs mais utile)
        raw_emails = set(_RE_EMAIL.findall(resp.text))

        page_emails = mailto_emails | {
            e for e in raw_emails
            if not e.endswith((".png", ".jpg", ".gif", ".css", ".js"))
            and len(e) < 80
        }

        if page_emails:
            log.info(f"  {path} → {page_emails}")
            all_emails |= page_emails

    if all_emails:
        report.add_finding(
            module="recon.email_harvester",
            severity=Severity.MEDIUM,
            title=f"{len(all_emails)} adresse(s) email exposée(s)",
            detail="Des adresses email ont été trouvées dans le contenu public du site.",
            evidence={"emails": sorted(all_emails), "target": base_url},
        )
    else:
        log.info("  Aucun email trouvé.")

    return all_emails
