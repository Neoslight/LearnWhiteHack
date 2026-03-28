"""Détection de Host Header Injection, SSRF basique et Open Redirect."""

from __future__ import annotations

import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("vuln.header_injection")

_TEST_HOST = "evil-test-probe.example.com"
_TEST_IP = "169.254.169.254"  # AWS IMDS, courant dans les tests SSRF

_OPEN_REDIRECT_PROBES = [
    "?redirect=https://evil-test-probe.example.com",
    "?url=https://evil-test-probe.example.com",
    "?next=https://evil-test-probe.example.com",
    "?return=https://evil-test-probe.example.com",
    "?goto=https://evil-test-probe.example.com",
    "?redir=https://evil-test-probe.example.com",
    "?r=https://evil-test-probe.example.com",
    "?to=https://evil-test-probe.example.com",
]


def run(cfg: AppConfig, report: Report) -> None:
    """Teste Host Header Injection et Open Redirect."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return

    log.info(f"[bold]vuln.header_injection[/] → {base_url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    # --- Host Header Injection ---
    try:
        resp = session.get(
            base_url,
            headers={"Host": _TEST_HOST},
            timeout=cfg.http.timeout,
            allow_redirects=False,
        )
        # Vérifier si le Host injecté apparaît dans la réponse ou les headers
        location = resp.headers.get("Location", "")
        body_excerpt = resp.text[:1000]

        if _TEST_HOST in location or _TEST_HOST in body_excerpt:
            log.info(f"  [red]Host Header Injection possible[/]")
            report.add_finding(
                module="vuln.header_injection",
                severity=Severity.HIGH,
                title="Host Header Injection détectée",
                detail=(
                    f"Le serveur reflète le header Host manipulé ({_TEST_HOST}) "
                    "dans sa réponse. Vecteur d'attaque potentiel pour password reset poisoning."
                ),
                evidence={
                    "url": base_url,
                    "injected_host": _TEST_HOST,
                    "location_header": location,
                    "body_reflection": _TEST_HOST in body_excerpt,
                },
                references=["https://portswigger.net/web-security/host-header"],
            )
        else:
            log.debug("  Host Header Injection : pas de réflexion détectée")
    except Exception as e:
        log.debug(f"Erreur Host Header test: {e}")

    # --- X-Forwarded-For / X-Real-IP bypass ---
    bypass_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-Host": _TEST_HOST},
    ]
    for extra_headers in bypass_headers:
        try:
            resp = session.get(
                base_url,
                headers=extra_headers,
                timeout=cfg.http.timeout,
                allow_redirects=False,
            )
            header_name = list(extra_headers.keys())[0]
            val = list(extra_headers.values())[0]
            if val in resp.text[:500] or val in resp.headers.get("Location", ""):
                log.info(f"  [yellow]Réflexion header[/] {header_name}: {val}")
                report.add_finding(
                    module="vuln.header_injection",
                    severity=Severity.MEDIUM,
                    title=f"Réflexion du header {header_name}",
                    detail=f"La valeur du header {header_name} est reflétée dans la réponse.",
                    evidence={"header": header_name, "value": val},
                )
        except Exception:
            pass

    # --- Open Redirect ---
    for probe in _OPEN_REDIRECT_PROBES:
        url = base_url + probe
        try:
            resp = session.get(url, timeout=cfg.http.timeout, allow_redirects=False)
            location = resp.headers.get("Location", "")
            if "evil-test-probe.example.com" in location:
                log.info(f"  [red]Open Redirect détecté[/] : {probe}")
                report.add_finding(
                    module="vuln.header_injection",
                    severity=Severity.MEDIUM,
                    title=f"Open Redirect détecté : {probe.split('=')[0]}",
                    detail=(
                        f"Le paramètre {probe.split('=')[0]} permet une redirection vers "
                        "un domaine externe arbitraire."
                    ),
                    evidence={
                        "url": url,
                        "location": location,
                        "status_code": resp.status_code,
                    },
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                )
        except Exception as e:
            log.debug(f"Erreur probe {probe}: {e}")
