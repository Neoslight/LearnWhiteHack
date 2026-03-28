"""Agrège tous les usernames trouvés en une liste dédupliquée pour usage offline."""

from __future__ import annotations

from pathlib import Path

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("wordpress.user_bruteforce_prep")


def run(
    cfg: AppConfig,
    report: Report,
    users_from_api: list[dict[str, object]] | None = None,
    users_from_archives: list[dict[str, object]] | None = None,
    extra_usernames: list[str] | None = None,
    output_file: str | None = None,
) -> list[str]:
    """Agrège et déduplique les usernames collectés par tous les modules WP."""
    all_names: set[str] = set()

    if users_from_api:
        for u in users_from_api:
            if slug := u.get("slug"):
                all_names.add(str(slug))
            if name := u.get("name"):
                all_names.add(str(name).lower().replace(" ", "."))

    if users_from_archives:
        for u in users_from_archives:
            if slug := u.get("slug"):
                all_names.add(str(slug))

    if extra_usernames:
        all_names.update(extra_usernames)

    # Ajouter les variantes communes
    common_admins = ["admin", "administrator", "webmaster", "root", "wp-admin"]
    all_names.update(common_admins)

    sorted_names = sorted(all_names)
    log.info(f"[bold]wp.user_bruteforce_prep[/] — {len(sorted_names)} username(s) agrégé(s)")

    # Écriture du fichier si demandé
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(sorted_names), encoding="utf-8")
        log.info(f"  Liste sauvegardée : {out_path}")

    if sorted_names:
        report.add_finding(
            module="wordpress.user_bruteforce_prep",
            severity=Severity.MEDIUM,
            title=f"Liste d'utilisateurs WordPress prête ({len(sorted_names)} entrées)",
            detail=(
                "Compilation de tous les noms d'utilisateurs identifiés. "
                "Cette liste peut être utilisée avec des outils comme Hydra, WPScan "
                "ou Burp Suite Intruder sur des cibles de test autorisées."
            ),
            evidence={
                "usernames": sorted_names,
                "output_file": output_file or "(non sauvegardé)",
            },
        )

    return sorted_names
