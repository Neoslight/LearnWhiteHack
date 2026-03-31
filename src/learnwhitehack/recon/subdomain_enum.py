"""Énumération de sous-domaines : Certificate Transparency (crt.sh) + DNS bruteforce."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Optional

import requests

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity
from learnwhitehack.core.state import ScanContext

log = get_logger("recon.subdomain_enum")

_DEFAULT_WORDLIST = Path(__file__).parent / "wordlists" / "subdomains.txt"

_CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"


def _query_crtsh(domain: str, timeout: int = 15) -> set[str]:
    """Interroge crt.sh pour trouver les sous-domaines via Certificate Transparency."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains: set[str] = set()
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "learnwhitehack/0.1"})
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub and domain in sub:
                        subdomains.add(sub)
    except Exception as e:
        log.debug(f"Erreur crt.sh: {e}")
    return subdomains


def _dns_resolve(hostname: str) -> str | None:
    """Résout un hostname en IP. Retourne None si pas de résolution."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def run(
    cfg: AppConfig,
    report: Report,
    wordlist_path: Path | None = None,
    bruteforce: bool = True,
    context: Optional[ScanContext] = None,
) -> list[dict[str, object]]:
    """Énumère les sous-domaines via crt.sh et bruteforce DNS."""
    from urllib.parse import urlparse

    url = cfg.target.url.rstrip("/")
    if not url:
        log.error("Aucune URL cible configurée.")
        return []

    domain = urlparse(url).hostname or ""
    # Extraire le domaine racine (2 derniers segments)
    parts = domain.split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = domain

    log.info(f"[bold]recon.subdomain_enum[/] → {root_domain}")
    found: dict[str, str] = {}

    # --- crt.sh ---
    log.info("  Interrogation crt.sh (Certificate Transparency)…")
    ct_subs = _query_crtsh(root_domain)
    log.info(f"  crt.sh : {len(ct_subs)} sous-domaine(s) trouvé(s)")
    for sub in ct_subs:
        ip = _dns_resolve(sub)
        if ip:
            found[sub] = ip

    # --- Bruteforce DNS ---
    if bruteforce:
        wl = wordlist_path or _DEFAULT_WORDLIST
        prefixes: list[str] = []
        if wl.exists():
            with open(wl, encoding="utf-8") as f:
                prefixes = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        else:
            # Wordlist minimale intégrée
            prefixes = [
                "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2",
                "dev", "staging", "test", "api", "cdn", "static", "assets",
                "admin", "portal", "vpn", "remote", "blog", "shop", "store",
                "app", "mobile", "m", "secure", "login", "auth", "beta",
                "dashboard", "panel", "cpanel", "whm", "webmail", "upload",
                "files", "img", "images", "media", "forum", "community",
            ]

        log.info(f"  Bruteforce DNS ({len(prefixes)} préfixes)…")
        for prefix in prefixes:
            hostname = f"{prefix}.{root_domain}"
            ip = _dns_resolve(hostname)
            if ip:
                log.debug(f"    {hostname} → {ip}")
                found[hostname] = ip

    # Résultats
    results = [{"subdomain": sub, "ip": ip} for sub, ip in sorted(found.items())]
    log.info(f"  {len(results)} sous-domaine(s) résolus")

    if results:
        report.add_finding(
            module="recon.subdomain_enum",
            severity=Severity.INFO,
            title=f"{len(results)} sous-domaine(s) découvert(s) pour {root_domain}",
            detail="Sous-domaines trouvés via Certificate Transparency (crt.sh) et bruteforce DNS.",
            evidence={"domain": root_domain, "subdomains": results[:50]},
        )

    if context is not None:
        context.subdomains_found = [r["subdomain"] for r in results]  # type: ignore[misc]

    return results
