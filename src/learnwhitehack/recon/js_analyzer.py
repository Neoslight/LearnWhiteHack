"""Analyse des fichiers JavaScript pour extraire endpoints, clés et URLs internes."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.js_analyzer")

_RE_JS_URL = re.compile(r'["\'`]([/][a-zA-Z0-9_\-./]+(?:\?[^"\'`\s]*)?)["\'`]')
_RE_API_KEY = re.compile(
    r'(?:api[_-]?key|apikey|token|secret|password|auth)["\s]*[=:]["\s]*([a-zA-Z0-9_\-./+]{16,})',
    re.IGNORECASE,
)
_RE_ENDPOINT = re.compile(r'(?:fetch|axios\.(?:get|post)|http\.(?:get|post))\s*\(["\']([^"\']+)["\']', re.IGNORECASE)
_RE_COMMENT_TODO = re.compile(r'//\s*(TODO|FIXME|HACK|BUG|XXX|PASSWORD|SECRET)[:\s].+', re.IGNORECASE)
_RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)


def _collect_js_urls(html: str, base_url: str) -> list[str]:
    """Extrait les URLs de scripts JS depuis le HTML."""
    js_urls: list[str] = []
    for m in _RE_SCRIPT_SRC.finditer(html):
        src = m.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = base_url.rstrip("/") + src
        elif not src.startswith("http"):
            src = urljoin(base_url, src)
        js_urls.append(src)
    return js_urls


def run(cfg: AppConfig, report: Report) -> None:
    """Analyse les fichiers JS de la cible pour trouver infos sensibles."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return

    log.info(f"[bold]recon.js_analyzer[/] → {base_url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    # Récupérer la page principale pour trouver les scripts
    try:
        resp = session.get(base_url, timeout=cfg.http.timeout)
    except Exception as e:
        log.error(f"Impossible de charger {base_url}: {e}")
        return

    js_urls = _collect_js_urls(resp.text, base_url)
    domain = urlparse(base_url).hostname or ""
    # Limiter aux scripts du même domaine ou relatifs
    local_js = [u for u in js_urls if domain in u or u.startswith(base_url)]
    log.info(f"  {len(local_js)} script(s) JS local(aux) trouvé(s)")

    all_endpoints: set[str] = set()
    all_keys: list[dict[str, str]] = []
    all_comments: list[str] = []
    all_internal_urls: set[str] = set()

    for js_url in local_js[:20]:  # limiter à 20 scripts
        try:
            js_resp = session.get(js_url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {js_url}: {e}")
            continue

        if js_resp.status_code != 200:
            continue

        content = js_resp.text

        # Endpoints API
        for m in _RE_ENDPOINT.finditer(content):
            all_endpoints.add(m.group(1))

        # URLs internes
        for m in _RE_JS_URL.finditer(content):
            url_candidate = m.group(1)
            if len(url_candidate) > 2 and "." not in url_candidate.split("/")[-1][:3]:
                all_internal_urls.add(url_candidate)

        # Clés/tokens
        for m in _RE_API_KEY.finditer(content):
            val = m.group(1)
            context = content[max(0, m.start() - 30):m.end() + 30]
            all_keys.append({"value": val[:50], "context": context[:100], "file": js_url})

        # Commentaires suspects
        for m in _RE_COMMENT_TODO.finditer(content):
            all_comments.append(m.group(0)[:100])

    if all_endpoints:
        log.info(f"  Endpoints API détectés : {len(all_endpoints)}")
        report.add_finding(
            module="recon.js_analyzer",
            severity=Severity.LOW,
            title=f"{len(all_endpoints)} endpoint(s) API dans les fichiers JS",
            detail="Des URLs d'endpoints API ont été extraites des fichiers JavaScript.",
            evidence={"endpoints": sorted(all_endpoints)[:30]},
        )

    if all_keys:
        log.info(f"  [red]Clés/tokens potentiels : {len(all_keys)}[/]")
        report.add_finding(
            module="recon.js_analyzer",
            severity=Severity.HIGH,
            title=f"{len(all_keys)} clé(s)/token(s) potentiel(s) dans les fichiers JS",
            detail="Des patterns ressemblant à des clés API ou tokens ont été trouvés dans les JS.",
            evidence={"keys": all_keys[:10]},
        )

    if all_comments:
        log.info(f"  Commentaires suspects : {len(all_comments)}")
        report.add_finding(
            module="recon.js_analyzer",
            severity=Severity.LOW,
            title=f"{len(all_comments)} commentaire(s) suspect(s) dans les JS",
            detail="Des commentaires de debug (TODO, FIXME, BUG, SECRET…) ont été trouvés.",
            evidence={"comments": all_comments[:20]},
        )
