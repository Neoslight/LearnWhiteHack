"""Énumération des auteurs WordPress via redirections ?author=N."""

from __future__ import annotations

import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.author_archives")

_RE_AUTHOR_SLUG = re.compile(r"/author/([^/\"'?#\s]+)", re.IGNORECASE)


def run(cfg: AppConfig, report: Report, max_id: int = 10) -> None:
    """Énumère les auteurs WordPress via le paramètre ?author=N."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return

    log.info(f"[bold]author_archives[/] → {base_url} (IDs 1–{max_id})")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    found: list[dict[str, object]] = []

    for uid in range(1, max_id + 1):
        url = f"{base_url}/?author={uid}"
        try:
            resp = session.get(url, timeout=cfg.http.timeout, allow_redirects=True)
        except Exception as e:
            log.debug(f"Erreur UID {uid}: {e}")
            continue

        # Vérifier la présence d'un slug /author/xxx dans l'URL finale
        final_url = resp.url
        m = _RE_AUTHOR_SLUG.search(final_url)
        if m and resp.status_code == 200:
            slug = m.group(1)
            log.info(f"  [green]Auteur trouvé[/] ID={uid} → slug={slug}")
            found.append({"id": uid, "slug": slug, "profile_url": final_url})
        else:
            log.debug(f"  ID={uid} → pas d'auteur (HTTP {resp.status_code})")

    if found:
        report.add_finding(
            module="recon.author_archives",
            severity=Severity.MEDIUM,
            title=f"Auteurs WordPress énumérés ({len(found)} compte(s))",
            detail=(
                "L'énumération via ?author=N révèle des noms d'utilisateurs valides. "
                "Ces slugs peuvent être utilisés pour des attaques de brute-force sur wp-login.php."
            ),
            evidence={"users": found},
            references=["https://www.wpbeginner.com/wp-tutorials/how-to-stop-wordpress-author-enumeration/"],
        )
    else:
        log.info("  Aucun auteur détecté via redirections.")
        report.add_finding(
            module="recon.author_archives",
            severity=Severity.INFO,
            title="Énumération des auteurs : aucun résultat",
            detail="Les redirections ?author=N ne révèlent aucun slug utilisateur.",
            evidence={"tested_ids": list(range(1, max_id + 1))},
        )
