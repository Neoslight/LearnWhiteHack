"""Détection et test de l'interface XML-RPC WordPress."""

from __future__ import annotations

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("wordpress.xmlrpc_probe")

_XMLRPC_PATH = "/xmlrpc.php"

_PAYLOAD_LISTMETHODS = b"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""

_PAYLOAD_MULTICALL = b"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param><value><array><data>
      <value><struct>
        <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
        <member><name>params</name><value><array><data>
          <value><array><data>
            <value><string>admin</string></value>
            <value><string>password</string></value>
          </data></array></value>
        </data></array></value></member>
      </struct></value>
    </data></array></value></param>
  </params>
</methodCall>"""


def run(cfg: AppConfig, report: Report) -> bool:
    """Détecte si XML-RPC est actif et teste les méthodes exposées."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return False

    url = base_url + _XMLRPC_PATH
    log.info(f"[bold]wordpress.xmlrpc_probe[/] → {url}")

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    # Test GET simple
    try:
        resp = session.get(url, timeout=cfg.http.timeout)
    except Exception as e:
        log.debug(f"Erreur GET {url}: {e}")
        return False

    if resp.status_code not in (200, 405):
        log.info(f"  xmlrpc.php → {resp.status_code} (probablement absent ou bloqué)")
        return False

    log.info(f"  [yellow]xmlrpc.php présent[/] (HTTP {resp.status_code})")

    # Lister les méthodes disponibles
    methods: list[str] = []
    try:
        post_resp = session.post(
            url,
            data=_PAYLOAD_LISTMETHODS,
            headers={"Content-Type": "text/xml"},
            timeout=cfg.http.timeout,
        )
        if post_resp.status_code == 200 and "<methodResponse>" in post_resp.text:
            import re
            methods = re.findall(r"<string>([^<]+)</string>", post_resp.text)
            log.info(f"  {len(methods)} méthode(s) listée(s)")
    except Exception as e:
        log.debug(f"Erreur listMethods: {e}")

    # Test multicall (vecteur de bruteforce en une requête)
    multicall_enabled = False
    if "system.multicall" in methods:
        multicall_enabled = True
        log.info(f"  [red]system.multicall activé — bruteforce amplifié possible[/]")

    severity = Severity.HIGH if multicall_enabled else Severity.MEDIUM

    report.add_finding(
        module="wordpress.xmlrpc_probe",
        severity=severity,
        title="XML-RPC WordPress activé" + (" (multicall = bruteforce amplifié possible)" if multicall_enabled else ""),
        detail=(
            "Le fichier xmlrpc.php est accessible. "
            "XML-RPC permet d'effectuer des attaques de brute-force via system.multicall "
            "et peut être utilisé pour des attaques SSRF via pingback."
        ),
        evidence={
            "url": url,
            "methods_count": len(methods),
            "methods_sample": methods[:20],
            "multicall_enabled": multicall_enabled,
        },
        references=[
            "https://www.wordfence.com/learn/wordpress-xmlrpc-security/",
            "https://owasp.org/www-community/attacks/XML-RPC_Server_Side_Request_Forgery",
        ],
    )

    return True
