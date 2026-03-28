"""Détection de fichiers de configuration et backups exposés sur WordPress."""

from __future__ import annotations

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("wordpress.config_leaks")

# (chemin, sévérité, description)
_SENSITIVE_FILES: list[tuple[str, Severity, str]] = [
    # Config WordPress
    ("/wp-config.php",          Severity.CRITICAL, "Configuration principale WP (credentials DB)"),
    ("/wp-config.php.bak",      Severity.CRITICAL, "Backup de wp-config.php exposé"),
    ("/wp-config.php.old",      Severity.CRITICAL, "Ancienne version wp-config.php exposée"),
    ("/wp-config.php~",         Severity.CRITICAL, "Fichier temporaire wp-config.php exposé"),
    ("/wp-config-sample.php",   Severity.LOW,      "Fichier sample wp-config.php"),
    # Logs
    ("/debug.log",              Severity.HIGH, "Log de debug WordPress exposé"),
    ("/error_log",              Severity.HIGH, "Log d'erreurs exposé"),
    ("/wp-content/debug.log",   Severity.HIGH, "Log de debug dans wp-content"),
    # Git
    ("/.git/config",            Severity.HIGH, "Dépôt Git exposé (config)"),
    ("/.git/HEAD",              Severity.HIGH, "Dépôt Git exposé (HEAD)"),
    ("/.gitignore",             Severity.LOW,  ".gitignore exposé"),
    # Env
    ("/.env",                   Severity.CRITICAL, "Fichier .env exposé (credentials)"),
    ("/.env.local",             Severity.CRITICAL, "Fichier .env.local exposé"),
    ("/.env.production",        Severity.CRITICAL, "Fichier .env.production exposé"),
    # Backups
    ("/backup.sql",             Severity.CRITICAL, "Backup SQL exposé"),
    ("/database.sql",           Severity.CRITICAL, "Base de données SQL exposée"),
    ("/backup.zip",             Severity.HIGH, "Archive backup exposée"),
    ("/site.zip",               Severity.HIGH, "Archive site exposée"),
    ("/wp-content/uploads/backup.sql", Severity.CRITICAL, "Backup SQL dans uploads"),
    # PHP info
    ("/phpinfo.php",            Severity.HIGH, "phpinfo() exposé"),
    ("/info.php",               Severity.HIGH, "phpinfo() exposé"),
    ("/test.php",               Severity.MEDIUM, "Fichier test.php exposé"),
    # Composer / Node
    ("/composer.json",          Severity.LOW,  "composer.json exposé (dépendances)"),
    ("/composer.lock",          Severity.LOW,  "composer.lock exposé"),
    ("/package.json",           Severity.LOW,  "package.json exposé"),
    # Divers
    ("/xmlrpc.php",             Severity.MEDIUM, "XML-RPC actif"),
    ("/wp-cron.php",            Severity.LOW,  "wp-cron.php accessible directement"),
    ("/wp-login.php",           Severity.INFO, "wp-login.php accessible (normal mais utile à noter)"),
    ("/wp-admin/",              Severity.INFO, "Panel admin accessible"),
    ("/wp-json/",               Severity.INFO, "API REST accessible"),
]


def run(cfg: AppConfig, report: Report) -> list[str]:
    """Cherche les fichiers sensibles exposés sur WordPress."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    log.info(f"[bold]wordpress.config_leaks[/] → {base_url} ({len(_SENSITIVE_FILES)} fichiers)")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    found: list[str] = []

    for path, severity, description in _SENSITIVE_FILES:
        url = base_url + path
        try:
            resp = session.get(url, timeout=cfg.http.timeout, allow_redirects=False)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code == 200:
            log.info(f"  [red]EXPOSÉ[/] [{severity.value}] {path}")
            found.append(url)
            report.add_finding(
                module="wordpress.config_leaks",
                severity=severity,
                title=f"Fichier sensible exposé : {path}",
                detail=description,
                evidence={
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "body_preview": resp.text[:200] if severity != Severity.CRITICAL else "[REDACTED - contenu sensible]",
                },
            )
        elif resp.status_code == 403:
            log.debug(f"  403 (protégé) : {path}")
        else:
            log.debug(f"  {resp.status_code} : {path}")

    if not found:
        log.info("  Aucun fichier sensible exposé détecté.")

    return found
