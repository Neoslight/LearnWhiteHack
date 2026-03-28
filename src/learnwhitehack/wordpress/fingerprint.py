"""Fingerprinting WordPress : version, thèmes, plugins."""

from __future__ import annotations

import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("wordpress.fingerprint")

_RE_WP_VERSION_META = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)["\']',
    re.IGNORECASE,
)
_RE_WP_VERSION_LINK = re.compile(r'\?ver=([\d.]+)', re.IGNORECASE)
_RE_THEME = re.compile(r'/wp-content/themes/([^/"\'\s?]+)', re.IGNORECASE)
_RE_PLUGIN = re.compile(r'/wp-content/plugins/([^/"\'\s?]+)', re.IGNORECASE)

VERSION_ENDPOINTS = [
    "/",
    "/readme.html",
    "/wp-login.php",
    "/wp-admin/",
    "/feed/",
]


def run(cfg: AppConfig, report: Report) -> dict[str, object]:
    """Détecte la version WP, les thèmes et plugins actifs."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return {}

    log.info(f"[bold]wp.fingerprint[/] → {base_url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    wp_version: str | None = None
    themes: set[str] = set()
    plugins: set[str] = set()

    for path in VERSION_ENDPOINTS:
        url = base_url + path
        try:
            resp = session.get(url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code not in (200, 301, 302):
            continue

        html = resp.text

        # Version via meta generator
        if not wp_version:
            m = _RE_WP_VERSION_META.search(html)
            if m:
                wp_version = m.group(1)
                log.info(f"  [green]Version WP (meta)[/] : {wp_version} — {path}")

        # Thèmes
        for t in _RE_THEME.findall(html):
            themes.add(t)

        # Plugins
        for p in _RE_PLUGIN.findall(html):
            plugins.add(p)

    # Vérification readme.html pour version si pas trouvée
    if not wp_version:
        try:
            resp = session.get(base_url + "/readme.html", timeout=cfg.http.timeout)
            if resp.status_code == 200:
                m = re.search(r'Version\s+([\d.]+)', resp.text, re.IGNORECASE)
                if m:
                    wp_version = m.group(1)
                    log.info(f"  [green]Version WP (readme.html)[/] : {wp_version}")
                    report.add_finding(
                        module="wordpress.fingerprint",
                        severity=Severity.MEDIUM,
                        title="readme.html exposé avec version WordPress",
                        detail=f"Le fichier readme.html révèle la version WordPress {wp_version}.",
                        evidence={"url": base_url + "/readme.html"},
                        references=["https://wordpress.org/support/article/hardening-wordpress/"],
                    )
        except Exception:
            pass

    if wp_version:
        report.add_finding(
            module="wordpress.fingerprint",
            severity=Severity.MEDIUM,
            title=f"Version WordPress divulguée : {wp_version}",
            detail="La version de WordPress est identifiable publiquement via les sources HTML.",
            evidence={"version": wp_version, "target": base_url},
            references=["https://wpscan.com/"],
        )
    else:
        log.info("  Version WordPress non détectée.")

    if themes:
        log.info(f"  Thèmes détectés : {themes}")
        report.add_finding(
            module="wordpress.fingerprint",
            severity=Severity.INFO,
            title=f"Thèmes WordPress détectés ({len(themes)})",
            detail="Les noms de thèmes sont visibles dans les sources HTML.",
            evidence={"themes": sorted(themes)},
        )

    if plugins:
        log.info(f"  Plugins détectés : {plugins}")
        report.add_finding(
            module="wordpress.fingerprint",
            severity=Severity.LOW,
            title=f"Plugins WordPress détectés ({len(plugins)})",
            detail="Les noms de plugins sont visibles dans les sources HTML.",
            evidence={"plugins": sorted(plugins)},
        )

    return {
        "version": wp_version,
        "themes": sorted(themes),
        "plugins": sorted(plugins),
    }
