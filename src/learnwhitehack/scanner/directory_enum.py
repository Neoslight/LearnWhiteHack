"""Bruteforce de chemins HTTP (style Dirbuster/Gobuster) avec rate limiting."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("scanner.directory_enum")

_DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "common.txt"
_RE_TITLE = re.compile(r"<title>([^<]{1,100})</title>", re.IGNORECASE)

# Chemins courants intégrés (utilisés si wordlist absente)
_BUILTIN_PATHS = [
    "admin", "administrator", "login", "wp-admin", "dashboard",
    "panel", "cpanel", "phpmyadmin", "pma", "setup", "install",
    "backup", "backups", "db", "database", "config", "configuration",
    "api", "api/v1", "api/v2", "rest", "graphql", "swagger", "swagger-ui",
    "docs", "documentation", "readme", "changelog", "test", "tests",
    "dev", "development", "staging", "beta", "old", "new", "temp",
    "upload", "uploads", "files", "file", "media", "images", "img",
    "assets", "static", "public", "private", "internal", "hidden",
    "secret", ".git", ".env", ".htaccess", ".htpasswd", "web.config",
    "sitemap.xml", "robots.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    "server-status", "server-info", "_profiler", "phpinfo.php",
    "info.php", "test.php", "1.php", "shell.php", "cmd.php",
    "wp-content", "wp-includes", "wp-login.php", "wp-cron.php",
    "xmlrpc.php", "wp-json", "wp-sitemap.xml",
]


def _check_path(session: object, base_url: str, path: str, timeout: int) -> dict[str, object] | None:
    """Teste un chemin et retourne les infos si intéressant."""
    import requests
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = (session).get(url, timeout=timeout, allow_redirects=False)  # type: ignore[attr-defined]
        code = resp.status_code
        if code in (200, 204, 301, 302, 307, 308, 401, 403):
            title_match = _RE_TITLE.search(resp.text[:2000]) if code == 200 else None
            return {
                "path": "/" + path.lstrip("/"),
                "url": url,
                "status": code,
                "size": len(resp.content),
                "title": title_match.group(1).strip() if title_match else "",
                "redirect": resp.headers.get("Location", "") if code in (301, 302, 307, 308) else "",
            }
    except Exception:
        pass
    return None


def run(
    cfg: AppConfig,
    report: Report,
    wordlist_path: Path | None = None,
    extensions: list[str] | None = None,
    threads: int = 20,
) -> list[dict[str, object]]:
    """Bruteforce les chemins HTTP sur la cible."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    # Charger wordlist
    wl = wordlist_path or _DEFAULT_WORDLIST
    paths: list[str] = list(_BUILTIN_PATHS)
    if wl.exists():
        with open(wl, encoding="utf-8", errors="ignore") as f:
            paths += [l.strip() for l in f if l.strip() and not l.startswith("#")]

    # Ajouter extensions
    if extensions:
        expanded: list[str] = list(paths)
        for p in list(paths):
            for ext in extensions:
                expanded.append(f"{p}.{ext.lstrip('.')}")
        paths = expanded

    paths = list(dict.fromkeys(paths))  # déduplication

    log.info(
        f"[bold]scanner.directory_enum[/] → {base_url} "
        f"({len(paths)} chemins, {threads} threads)"
    )

    session = make_session(
        min_delay=0.1,
        max_delay=0.5,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    results: list[dict[str, object]] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_check_path, session, base_url, p, cfg.http.timeout): p
            for p in paths
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                code = result["status"]
                icon = "[green]200[/]" if code == 200 else f"[yellow]{code}[/]"
                log.info(f"  {icon} {result['path']} ({result['size']}B) {result['title']}")
                results.append(result)

    if results:
        # Séparer 200/403/redirects
        found_200 = [r for r in results if r["status"] == 200]
        found_403 = [r for r in results if r["status"] == 403]
        found_redirect = [r for r in results if r["status"] in (301, 302, 307, 308)]

        if found_200:
            report.add_finding(
                module="scanner.directory_enum",
                severity=Severity.MEDIUM,
                title=f"{len(found_200)} chemin(s) accessibles (HTTP 200)",
                detail="Des chemins HTTP retournent 200 OK.",
                evidence={"paths": found_200[:50]},
            )
        if found_403:
            report.add_finding(
                module="scanner.directory_enum",
                severity=Severity.LOW,
                title=f"{len(found_403)} chemin(s) protégés (HTTP 403)",
                detail="Ces chemins existent mais sont protégés.",
                evidence={"paths": [r["path"] for r in found_403][:30]},
            )

    return results
