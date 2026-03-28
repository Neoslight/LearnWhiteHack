"""Fuzzing de chemins de plugins WordPress pour trouver fichiers exposés."""

from __future__ import annotations

import time
from pathlib import Path

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("wordpress.plugin_fuzzer")

_DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "plugin_paths.txt"

# Chemins sensibles à tester par plugin (relatif à /wp-content/plugins/{plugin}/)
_SENSITIVE_PATHS = [
    "readme.txt",
    "readme.md",
    "changelog.txt",
    "debug.log",
    "error.log",
    "export.xml",
    "backup.sql",
    "config.php.bak",
    ".env",
    "install.php",
    "uninstall.php",
    "test.php",
    "phpinfo.php",
    "info.php",
]


def run(
    cfg: AppConfig,
    report: Report,
    plugins: list[str] | None = None,
    wordlist_path: Path | None = None,
) -> None:
    """Fuzz les chemins de plugins WordPress pour trouver fichiers exposés."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return

    # Charger wordlist ou utiliser les plugins passés
    target_plugins: list[str] = list(plugins or [])
    wl = wordlist_path or _DEFAULT_WORDLIST
    if wl.exists():
        with open(wl, encoding="utf-8") as f:
            target_plugins += [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not target_plugins:
        log.warning("Aucun plugin à fuzzer. Fournir --plugins ou une wordlist.")
        return

    target_plugins = list(dict.fromkeys(target_plugins))  # déduplication
    log.info(
        f"[bold]wp.plugin_fuzzer[/] → {base_url} "
        f"({len(target_plugins)} plugins × {len(_SENSITIVE_PATHS)} chemins)"
    )

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    # Endpoints REST connus à tester aussi
    rest_endpoints = [
        "/wp-json/ssp/v1/episodes",
        "/wp-json/wp/v2/posts?per_page=100",
        "/wp-json/wp/v2/media?per_page=100",
        "/wp-json/wp/v2/categories",
        "/wp-json/wp/v2/tags",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp-site-health/v1/tests",
        "/wp-json/oembed/1.0/embed",
    ]

    for endpoint in rest_endpoints:
        url = base_url + endpoint
        try:
            resp = session.get(url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue
        if resp.status_code == 200:
            log.info(f"  [green]Endpoint REST accessible[/] : {endpoint}")
            report.add_finding(
                module="wordpress.plugin_fuzzer",
                severity=Severity.LOW,
                title=f"Endpoint REST exposé : {endpoint}",
                detail=f"L'endpoint {endpoint} retourne HTTP 200.",
                evidence={"url": url, "status_code": 200, "body_preview": resp.text[:200]},
            )

    for plugin in target_plugins:
        for sensitive_path in _SENSITIVE_PATHS:
            url = f"{base_url}/wp-content/plugins/{plugin}/{sensitive_path}"
            try:
                resp = session.get(url, timeout=cfg.http.timeout)
            except Exception as e:
                log.debug(f"Erreur {url}: {e}")
                continue

            if resp.status_code == 200:
                log.info(f"  [red]EXPOSÉ[/] {plugin}/{sensitive_path}")
                severity = Severity.HIGH if sensitive_path in (
                    "debug.log", "error.log", "export.xml", "backup.sql",
                    "config.php.bak", ".env",
                ) else Severity.MEDIUM

                report.add_finding(
                    module="wordpress.plugin_fuzzer",
                    severity=severity,
                    title=f"Fichier sensible exposé : {plugin}/{sensitive_path}",
                    detail=f"Le fichier {sensitive_path} du plugin {plugin} est accessible sans authentification.",
                    evidence={
                        "url": url,
                        "status_code": 200,
                        "plugin": plugin,
                        "file": sensitive_path,
                        "body_preview": resp.text[:300],
                    },
                )
            elif resp.status_code == 403:
                log.debug(f"  403 (protégé) : {plugin}/{sensitive_path}")
