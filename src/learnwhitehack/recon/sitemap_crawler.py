"""Extraction d'URLs depuis sitemap.xml, sitemap_index.xml et robots.txt."""

from __future__ import annotations

import re
from xml.etree import ElementTree

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.sitemap_crawler")

_SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
_RE_DISALLOW = re.compile(r"^Disallow:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_RE_SITEMAP_REF = re.compile(r"^Sitemap:\s*(.+)$", re.MULTILINE | re.IGNORECASE)


def _parse_sitemap_xml(content: str) -> list[str]:
    """Parse un fichier sitemap.xml ou sitemap_index.xml et retourne les URLs."""
    urls: list[str] = []
    try:
        root = ElementTree.fromstring(content)
        # sitemap_index
        for sm in root.findall(f"{_SITEMAP_NS}sitemap/{_SITEMAP_NS}loc"):
            urls.append(sm.text or "")
        # urlset
        for url in root.findall(f"{_SITEMAP_NS}url/{_SITEMAP_NS}loc"):
            urls.append(url.text or "")
    except ElementTree.ParseError:
        # Fallback regex
        urls = re.findall(r"<loc>(.*?)</loc>", content, re.IGNORECASE)
    return [u.strip() for u in urls if u.strip()]


def run(cfg: AppConfig, report: Report) -> list[str]:
    """Cartographie les URLs via sitemap et robots.txt."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    log.info(f"[bold]recon.sitemap_crawler[/] → {base_url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    all_urls: set[str] = set()
    disallowed: list[str] = []

    # --- robots.txt ---
    try:
        resp = session.get(f"{base_url}/robots.txt", timeout=cfg.http.timeout)
        if resp.status_code == 200:
            log.info(f"  robots.txt trouvé")
            disallowed = _RE_DISALLOW.findall(resp.text)
            sitemap_refs = _RE_SITEMAP_REF.findall(resp.text)
            if disallowed:
                log.info(f"  {len(disallowed)} chemins Disallow dans robots.txt")
                report.add_finding(
                    module="recon.sitemap_crawler",
                    severity=Severity.LOW,
                    title=f"{len(disallowed)} chemin(s) Disallow dans robots.txt",
                    detail="Les chemins Disallow peuvent indiquer des zones sensibles.",
                    evidence={
                        "url": f"{base_url}/robots.txt",
                        "disallowed_paths": disallowed[:30],
                    },
                )
    except Exception as e:
        log.debug(f"Erreur robots.txt: {e}")

    # --- Sitemaps ---
    sitemap_paths = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap-index.xml",
        "/wp-sitemap.xml",
        "/news-sitemap.xml",
        "/page-sitemap.xml",
        "/post-sitemap.xml",
        "/category-sitemap.xml",
    ]

    for path in sitemap_paths:
        url = base_url + path
        try:
            resp = session.get(url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code == 200:
            log.info(f"  Sitemap trouvé : {path}")
            urls = _parse_sitemap_xml(resp.text)
            log.info(f"    → {len(urls)} URL(s)")
            all_urls.update(urls[:200])

    if all_urls:
        report.add_finding(
            module="recon.sitemap_crawler",
            severity=Severity.INFO,
            title=f"{len(all_urls)} URL(s) dans les sitemaps",
            detail="La cartographie des URLs via sitemap.xml est complète.",
            evidence={"total_urls": len(all_urls), "sample": sorted(all_urls)[:30]},
        )

    return sorted(all_urls)
