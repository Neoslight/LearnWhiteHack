"""Énumération des utilisateurs via l'API REST WordPress."""

from __future__ import annotations

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("wordpress.api_users")

API_ENDPOINTS = [
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/users?per_page=100",
    "/?rest_route=/wp/v2/users",
]


def run(cfg: AppConfig, report: Report) -> list[dict[str, object]]:
    """Énumère les utilisateurs via l'API REST WP."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    log.info(f"[bold]wp.api_users[/] → {base_url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    users: list[dict[str, object]] = []

    for endpoint in API_ENDPOINTS:
        url = base_url + endpoint
        try:
            resp = session.get(url, timeout=cfg.http.timeout)
        except Exception as e:
            log.debug(f"Erreur {url}: {e}")
            continue

        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and data:
                    for u in data:
                        users.append({
                            "id": u.get("id"),
                            "name": u.get("name"),
                            "slug": u.get("slug"),
                            "link": u.get("link"),
                        })
                    log.info(f"  [green]API REST ouverte[/] : {len(users)} utilisateur(s) exposé(s)")
                    break
            except Exception as e:
                log.debug(f"Erreur parsing JSON {url}: {e}")
        elif resp.status_code in (401, 403):
            log.info(f"  API REST protégée ({resp.status_code}) : {endpoint}")
            report.add_finding(
                module="wordpress.api_users",
                severity=Severity.INFO,
                title="API REST WP protégée",
                detail=f"L'endpoint {endpoint} retourne {resp.status_code}. L'énumération REST est bloquée.",
                evidence={"url": url, "status_code": resp.status_code},
            )
        else:
            log.debug(f"  {resp.status_code} : {endpoint}")

    if users:
        report.add_finding(
            module="wordpress.api_users",
            severity=Severity.HIGH,
            title=f"API REST WP expose {len(users)} utilisateur(s)",
            detail=(
                "L'endpoint /wp-json/wp/v2/users est accessible sans authentification. "
                "Les slugs et noms d'utilisateurs peuvent être utilisés pour du brute-force."
            ),
            evidence={"users": users, "endpoint": base_url + API_ENDPOINTS[0]},
            references=[
                "https://developer.wordpress.org/rest-api/reference/users/",
                "https://www.wordfence.com/learn/wordpress-rest-api-security/",
            ],
        )

    return users
