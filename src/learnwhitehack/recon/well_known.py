"""Énumération des fichiers .well-known sur une cible HTTP."""

from __future__ import annotations

import json

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.well_known")

WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/core/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/dnt-policy.txt",
    "/.well-known/host-meta",
    "/.well-known/nodeinfo",
    "/.well-known/webfinger",
    "/.well-known/caldav",
    "/.well-known/carddav",
    "/.well-known/brave-rewards-verification.txt",
    "/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/crossdomain.xml",
    "/humans.txt",
    "/.git/config",
    "/.env",
    "/readme.html",
    "/readme.txt",
    "/wp-readme.php",
    "/error_log",
    "/debug.log",
]


def run(cfg: AppConfig, report: Report) -> None:
    """Scanne les fichiers .well-known et sensibles sur la cible."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return

    log.info(f"[bold]well_known[/] → {base_url} ({len(WELL_KNOWN_PATHS)} chemins)")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    for path in WELL_KNOWN_PATHS:
        url = base_url + path
        try:
            resp = session.get(url, timeout=cfg.http.timeout, allow_redirects=True)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            body_preview = resp.text[:300].strip()

            # Tenter de parser JSON
            parsed = None
            if "json" in content_type or body_preview.startswith("{"):
                try:
                    parsed = json.loads(resp.text)
                except json.JSONDecodeError:
                    pass

            # Déterminer la sévérité selon le fichier
            severity = Severity.INFO
            if any(s in path for s in [".env", ".git", "error_log", "debug.log"]):
                severity = Severity.HIGH
            elif "security.txt" in path or "openid" in path:
                severity = Severity.LOW

            log.info(f"  [green]TROUVÉ[/] {path} (HTTP {resp.status_code})")
            report.add_finding(
                module="recon.well_known",
                severity=severity,
                title=f"Fichier exposé : {path}",
                detail=f"Le fichier {path} est accessible publiquement.",
                evidence={
                    "url": url,
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "body_preview": body_preview[:200],
                    "parsed_json": parsed,
                },
            )
        elif resp.status_code == 403:
            log.debug(f"  403 (interdit mais présent) : {path}")
            report.add_finding(
                module="recon.well_known",
                severity=Severity.INFO,
                title=f"Ressource protégée (403) : {path}",
                detail="Le serveur retourne 403 — la ressource existe mais est protégée.",
                evidence={"url": url, "status_code": 403},
            )
        else:
            log.debug(f"  {resp.status_code} : {path}")
