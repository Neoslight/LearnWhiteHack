"""Extraction de métadonnées depuis les flux RSS et les readme de plugins."""

from __future__ import annotations

import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.rss_metadata")

_RE_EMAIL = re.compile(r"[\w.\-+]+@[\w.\-]+\.\w{2,}", re.IGNORECASE)
_RE_WP_PATH = re.compile(r"/[a-z0-9._\-/]*wp-content/[a-z0-9._\-/]+", re.IGNORECASE)
_RE_VERSION = re.compile(r"(?:Stable tag|Version)\s*:\s*([\d.]+)", re.IGNORECASE)

RSS_FEEDS = [
    "/feed/",
    "/feed/podcast/",
    "/feed/rss/",
    "/?feed=rss2",
]

PLUGIN_READMES = [
    "/wp-content/plugins/seriously-simple-podcasting/readme.txt",
    "/wp-content/plugins/seriously-simple-podcasting/readme.md",
]


def run(cfg: AppConfig, report: Report) -> None:
    """Extrait métadonnées (emails, chemins, versions) depuis RSS et readmes."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return

    log.info(f"[bold]rss_metadata[/] → {base_url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    # --- Readmes plugins ---
    for path in PLUGIN_READMES:
        url = base_url + path
        try:
            resp = session.get(url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code != 200:
            log.debug(f"  {resp.status_code} : {path}")
            continue

        log.info(f"  [green]readme plugin trouvé[/] : {path}")
        m = _RE_VERSION.search(resp.text)
        version = m.group(1) if m else "inconnue"

        report.add_finding(
            module="recon.rss_metadata",
            severity=Severity.INFO,
            title=f"Plugin readme accessible : {path}",
            detail=f"Version détectée : {version}",
            evidence={"url": url, "version": version, "body_preview": resp.text[:300]},
        )

    # --- Flux RSS ---
    all_emails: set[str] = set()
    all_paths: set[str] = set()

    for feed_path in RSS_FEEDS:
        url = base_url + feed_path
        try:
            resp = session.get(url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code != 200:
            log.debug(f"  {resp.status_code} : {feed_path}")
            continue

        log.info(f"  [green]flux RSS trouvé[/] : {feed_path}")
        emails = set(_RE_EMAIL.findall(resp.text))
        paths = set(_RE_WP_PATH.findall(resp.text))
        all_emails |= emails
        all_paths |= paths

    if all_emails:
        log.info(f"  Emails trouvés : {all_emails}")
        report.add_finding(
            module="recon.rss_metadata",
            severity=Severity.MEDIUM,
            title="Adresses email exposées dans le flux RSS",
            detail=f"{len(all_emails)} adresse(s) email trouvée(s) dans les flux RSS.",
            evidence={"emails": sorted(all_emails)},
        )

    if all_paths:
        log.info(f"  Chemins wp-content trouvés : {len(all_paths)}")
        report.add_finding(
            module="recon.rss_metadata",
            severity=Severity.LOW,
            title="Chemins internes wp-content exposés dans le flux RSS",
            detail=f"{len(all_paths)} chemin(s) de fichiers internes exposés.",
            evidence={"paths": sorted(all_paths)[:50]},
        )
