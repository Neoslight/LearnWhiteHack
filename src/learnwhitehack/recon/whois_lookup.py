"""WHOIS / RDAP : registrar, dates, nameservers, organisation, emails."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.whois_lookup")

_RDAP_URL = "https://rdap.verisign.com/com/v1/domain/{domain}"
_RDAP_FALLBACK = "https://rdap.org/domain/{domain}"
_RE_EMAIL = re.compile(r"[\w.\-+]+@[\w.\-]+\.\w{2,}", re.IGNORECASE)


def _query_rdap(domain: str, timeout: int = 10) -> dict[str, object] | None:
    """Interroge l'API RDAP pour un domaine."""
    for url_tpl in [_RDAP_FALLBACK]:
        try:
            url = url_tpl.format(domain=domain)
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "learnwhitehack/0.1"})
            if resp.status_code == 200:
                return resp.json()  # type: ignore[no-any-return]
        except Exception as e:
            log.debug(f"RDAP erreur {url_tpl}: {e}")
    return None


def run(cfg: AppConfig, report: Report) -> dict[str, object]:
    """Récupère les informations WHOIS/RDAP de la cible."""
    url = cfg.target.url.rstrip("/")
    if not url:
        log.error("Aucune URL cible configurée.")
        return {}

    hostname = urlparse(url).hostname or ""
    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    log.info(f"[bold]recon.whois_lookup[/] → {domain}")

    data = _query_rdap(domain, cfg.http.timeout)
    if not data:
        log.warning(f"RDAP n'a pas retourné de données pour {domain}")
        return {}

    # Extraction des informations clés
    registrar = ""
    creation_date = ""
    expiration_date = ""
    nameservers: list[str] = []
    emails: list[str] = []
    org = ""

    # Entités (registrar, registrant)
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])[1]
        for entry in vcard:
            if entry[0] == "fn":
                if "registrar" in roles:
                    registrar = entry[3]
                elif "registrant" in roles:
                    org = entry[3]
            if entry[0] == "email":
                emails.append(entry[3])

    # Dates
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration":
            creation_date = date
        elif action == "expiration":
            expiration_date = date

    # Nameservers
    for ns in data.get("nameservers", []):
        nameservers.append(ns.get("ldhName", "").lower())

    result = {
        "domain": domain,
        "registrar": registrar,
        "org": org,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "nameservers": nameservers,
        "emails": emails,
    }

    log.info(f"  Registrar: {registrar} | Org: {org}")
    log.info(f"  Création: {creation_date} | Expiration: {expiration_date}")
    log.info(f"  Nameservers: {nameservers}")

    severity = Severity.INFO
    if emails:
        log.info(f"  [yellow]Emails exposés via WHOIS[/] : {emails}")
        severity = Severity.LOW

    report.add_finding(
        module="recon.whois_lookup",
        severity=severity,
        title=f"Informations WHOIS/RDAP pour {domain}",
        detail=f"Registrar: {registrar}, Org: {org}, Expiration: {expiration_date}",
        evidence=result,
    )

    return result
