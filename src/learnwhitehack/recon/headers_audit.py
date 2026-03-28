"""Audit des headers HTTP de sécurité."""

from __future__ import annotations

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.headers_audit")

# (header, requis, sévérité si absent)
_SECURITY_HEADERS: list[tuple[str, bool, Severity]] = [
    ("Strict-Transport-Security", True,  Severity.HIGH),
    ("Content-Security-Policy",   True,  Severity.MEDIUM),
    ("X-Frame-Options",           True,  Severity.MEDIUM),
    ("X-Content-Type-Options",    True,  Severity.LOW),
    ("Referrer-Policy",           False, Severity.LOW),
    ("Permissions-Policy",        False, Severity.LOW),
    ("X-XSS-Protection",          False, Severity.INFO),
    ("Cross-Origin-Opener-Policy", False, Severity.LOW),
    ("Cross-Origin-Resource-Policy", False, Severity.LOW),
]

_LEAK_HEADERS = ["Server", "X-Powered-By", "X-Generator", "X-Pingback", "X-WordPress-Cache"]


def run(cfg: AppConfig, report: Report) -> None:
    """Audite les headers de sécurité et détecte les headers qui fuient des infos."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return

    log.info(f"[bold]recon.headers_audit[/] → {base_url}")

    session = make_session(
        min_delay=0,
        max_delay=0,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
        apply_jitter=False,
    )

    try:
        resp = session.get(base_url, timeout=cfg.http.timeout)
    except Exception as e:
        log.error(f"Impossible de joindre {base_url}: {e}")
        return

    headers = resp.headers

    # Headers manquants
    missing = []
    for header, required, sev in _SECURITY_HEADERS:
        if header.lower() not in {k.lower() for k in headers}:
            missing.append({"header": header, "required": required, "severity": sev.value})
            log.info(f"  [yellow]ABSENT[/] : {header} (sévérité: {sev.value})")
            report.add_finding(
                module="recon.headers_audit",
                severity=sev,
                title=f"Header de sécurité manquant : {header}",
                detail=f"Le header {header} n'est pas présent dans la réponse HTTP.",
                evidence={"url": base_url, "header": header},
                references=["https://securityheaders.com/"],
            )
        else:
            val = headers[header]
            log.debug(f"  OK : {header} = {val[:80]}")

    # Headers qui fuient des informations
    for header in _LEAK_HEADERS:
        val = headers.get(header, "")
        if val:
            log.info(f"  [red]FUITE[/] : {header} = {val}")
            report.add_finding(
                module="recon.headers_audit",
                severity=Severity.LOW,
                title=f"Header informatif exposé : {header}",
                detail=f"Le header {header} révèle des informations sur la stack technique : {val}",
                evidence={"url": base_url, "header": header, "value": val},
            )

    # Audit cookies
    for cookie in resp.cookies:
        flags = []
        if not cookie.secure:
            flags.append("Secure manquant")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("HttpOnly manquant")
        if cookie.has_nonstandard_attr("SameSite") is False:
            flags.append("SameSite manquant")
        if flags:
            log.info(f"  [yellow]Cookie non sécurisé[/] : {cookie.name} → {', '.join(flags)}")
            report.add_finding(
                module="recon.headers_audit",
                severity=Severity.MEDIUM,
                title=f"Cookie sans flags de sécurité : {cookie.name}",
                detail=f"Le cookie {cookie.name} est mal configuré : {', '.join(flags)}",
                evidence={"cookie": cookie.name, "flags_missing": flags},
            )
