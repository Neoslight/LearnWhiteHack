"""Détection du support HTTP/3 (QUIC) et analyse des opportunités de bypass WAF."""

from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("scanner.http3_audit")

# Tokens Alt-Svc indiquant le support HTTP/3
_RE_H3_TOKEN = re.compile(r"\bh3(?:-\d+)?\s*=\s*\"?:?\d+", re.IGNORECASE)

# Headers révélant la présence d'un WAF ou CDN sur le chemin HTTP/2
_WAF_HEADERS = [
    "cf-ray",           # Cloudflare
    "x-sucuri-id",      # Sucuri
    "x-sucuri-cache",
    "x-akamai-transformed",  # Akamai
    "x-imperva-id",     # Imperva
    "x-imperva",
    "x-waf",
    "x-cdn",
    "x-datadome",       # DataDome
    "x-shield",
]


def _parse_alt_svc(alt_svc: str) -> list[str]:
    """Extrait les tokens H3 depuis la valeur du header Alt-Svc."""
    tokens: list[str] = []
    for part in alt_svc.split(","):
        part = part.strip()
        if _RE_H3_TOKEN.match(part):
            tokens.append(part)
    return tokens


def _check_quic_udp(hostname: str, port: int = 443, timeout: float = 2.0) -> bool:
    """
    Tente une connexion UDP vers host:port pour vérifier la joignabilité réseau.
    Note : UDP connect() ne fait pas de handshake — teste uniquement la couche réseau.
    Envoie un byte de flag QUIC (long header) sans initier de vrai handshake TLS.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((hostname, port))
            # Premier byte d'un paquet QUIC Initial (long header flag)
            sock.send(b"\xc0" + b"\x00" * 3)
            return True
    except Exception:
        return False


def _try_httpx_h3(url: str, timeout: int) -> dict[str, object] | None:
    """
    Tente une requête via httpx si disponible (dépendance optionnelle).
    Retourne les infos de réponse ou None si httpx n'est pas installé.
    """
    try:
        import httpx  # type: ignore[import-not-found]  # dépendance optionnelle
    except ImportError:
        log.debug("httpx non installé — test de requête H3 ignoré.")
        return None

    try:
        with httpx.Client(http2=True, timeout=timeout) as client:
            resp = client.get(url)
            return {
                "http_version": str(resp.http_version),
                "status": resp.status_code,
                "server": resp.headers.get("server", ""),
            }
    except Exception as exc:
        log.debug(f"Requête httpx échouée: {exc}")
        return None


def run(cfg: AppConfig, report: Report) -> dict[str, object]:
    """Détecte le support HTTP/3 et évalue le risque de bypass WAF via QUIC."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return {}

    parsed = urlparse(base_url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    log.info(f"[bold]scanner.http3_audit[/] → {base_url}")

    session = make_session(
        min_delay=0,
        max_delay=0,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
        apply_jitter=False,
    )

    result: dict[str, object] = {
        "h3_advertised": False,
        "alt_svc_tokens": [],
        "alt_svc_raw": "",
        "quic_udp_reachable": False,
        "waf_headers_detected": [],
        "httpx_result": None,
    }

    # Étape 1 : Requête HTTP/2 ou HTTP/1.1 pour inspecter les headers
    try:
        resp = session.get(base_url, timeout=cfg.http.timeout)
    except Exception as exc:
        log.error(f"Impossible d'atteindre {base_url}: {exc}")
        return result

    alt_svc = resp.headers.get("Alt-Svc", "")
    h3_tokens = _parse_alt_svc(alt_svc)
    result["alt_svc_raw"] = alt_svc
    result["alt_svc_tokens"] = h3_tokens
    result["h3_advertised"] = len(h3_tokens) > 0

    # Détecter WAF/CDN sur le chemin HTTP/2
    response_headers_lower = [k.lower() for k in resp.headers.keys()]
    waf_hits = [h for h in _WAF_HEADERS if h in response_headers_lower]
    result["waf_headers_detected"] = waf_hits

    if not h3_tokens:
        log.info("  HTTP/3 non annoncé dans le header Alt-Svc.")
        return result

    log.info(f"  [green]HTTP/3 annoncé[/] : {h3_tokens}")

    # Étape 2 : Test de joignabilité UDP
    quic_reachable = _check_quic_udp(hostname, port, timeout=2.0)
    result["quic_udp_reachable"] = quic_reachable
    if quic_reachable:
        log.info(f"  [green]UDP {hostname}:{port} joignable[/] (QUIC potentiellement actif)")

    # Étape 3 : Requête httpx optionnelle
    httpx_result = _try_httpx_h3(base_url, cfg.http.timeout)
    result["httpx_result"] = httpx_result

    # Déterminer la sévérité selon la présence d'un WAF
    if not waf_hits:
        severity = Severity.MEDIUM
        title = "HTTP/3 annoncé — bypass WAF potentiel via QUIC"
        detail = (
            f"Le serveur annonce HTTP/3 ({', '.join(h3_tokens)}) mais aucun header WAF/CDN "
            "n'a été détecté sur le chemin HTTP/2. Un attaquant peut potentiellement accéder "
            "au service directement via QUIC en contournant les protections WAF."
        )
    else:
        severity = Severity.INFO
        title = f"Support HTTP/3 détecté ({', '.join(h3_tokens)})"
        detail = (
            f"Le serveur annonce HTTP/3 via Alt-Svc. "
            f"Headers WAF/CDN détectés sur le chemin H2 : {waf_hits}. "
            "Vérifier si le chemin H3 est également protégé."
        )

    report.add_finding(
        module="scanner.http3_audit",
        severity=severity,
        title=title,
        detail=detail,
        evidence={
            "url": base_url,
            "alt_svc": alt_svc,
            "h3_tokens": h3_tokens,
            "waf_headers": waf_hits,
            "quic_udp_reachable": quic_reachable,
            "httpx_result": httpx_result,
        },
        references=[
            "https://http3-explained.haxx.se/",
            "https://blog.cloudflare.com/http3-the-past-present-and-future/",
            "https://www.rfc-editor.org/rfc/rfc9114",
        ],
    )

    return result
