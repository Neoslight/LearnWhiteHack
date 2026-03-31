"""Détection d'opportunités de subdomain takeover."""

from __future__ import annotations

import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("vuln.subdomain_takeover")

# Fingerprints de services cloud "non réclamés" : service → pattern regex
_TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "GitHub Pages":  r"There isn't a GitHub Pages site here",
    "Heroku":        r"No such app|herokucdn\.com/error-pages/no-such-app",
    "Shopify":       r"Sorry, this shop is currently unavailable",
    "Fastly":        r"Fastly error: unknown domain",
    "AWS S3":        r"NoSuchBucket|The specified bucket does not exist",
    "Azure":         r"404 Web Site not found",
    "Zendesk":       r"Help Center Closed",
    "Tumblr":        r"Whatever you were looking for doesn't live here",
    "Ghost":         r"The thing you were looking for is no longer here",
    "Surge.sh":      r"project not found",
    "Pantheon":      r"The gods are wise, but do not know of the site which you seek",
    "Netlify":       r"Not Found - Request ID",
    "ReadMe":        r"Project doesnt exist yet",
    "Cargo":         r"If you're moving your domain away from Cargo",
}

# Compilation des patterns pour la performance
_COMPILED_FINGERPRINTS: dict[str, re.Pattern[str]] = {
    svc: re.compile(pat, re.IGNORECASE)
    for svc, pat in _TAKEOVER_FINGERPRINTS.items()
}

# Patterns de CNAME suspects pointant vers des services cloud
_CLOUD_CNAME_PATTERNS = [
    "github.io",
    "herokuapp.com",
    "myshopify.com",
    "fastly.net",
    "s3.amazonaws.com",
    "azurewebsites.net",
    "zendesk.com",
    "tumblr.com",
    "ghost.io",
    "surge.sh",
    "pantheon.io",
    "netlify.app",
    "readme.io",
    "cargocollective.com",
]


def _get_cname(hostname: str) -> str | None:
    """Résout le CNAME d'un hostname via dnspython. Retourne la cible ou None."""
    try:
        import dns.resolver  # type: ignore[import-untyped]  # déclaré dans pyproject.toml

        answers = dns.resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        return None


def _check_http_fingerprint(
    session: object, hostname: str, timeout: int
) -> tuple[str | None, str]:
    """
    Tente une requête HTTP/HTTPS vers le sous-domaine et recherche les fingerprints de takeover.
    Retourne (nom_du_service_si_vulnérable, extrait_réponse).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)  # type: ignore[attr-defined]
            text = resp.text[:3000]
            for service, pattern in _COMPILED_FINGERPRINTS.items():
                if pattern.search(text):
                    return service, text[:500]
        except Exception:
            continue
    return None, ""


def run(
    cfg: AppConfig,
    report: Report,
    subdomains: list[str] | None = None,
) -> list[dict[str, object]]:
    """
    Vérifie les sous-domaines pour des opportunités de takeover.
    Si subdomains est None, lance subdomain_enum automatiquement.
    """
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    # Auto-découverte si aucune liste fournie
    if subdomains is None:
        log.info("  Aucun sous-domaine fourni — lancement de subdomain_enum…")
        from learnwhitehack.recon import subdomain_enum  # import lazy (évite les imports circulaires)

        enum_results = subdomain_enum.run(cfg, report)
        subdomains = [str(r["subdomain"]) for r in enum_results if "subdomain" in r]

    if not subdomains:
        log.info("  Aucun sous-domaine à vérifier.")
        return []

    log.info(
        f"[bold]vuln.subdomain_takeover[/] → {base_url} "
        f"({len(subdomains)} sous-domaines)"
    )

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    results: list[dict[str, object]] = []

    for subdomain in subdomains:
        # Étape 1 : Résolution CNAME
        cname = _get_cname(subdomain)
        cname_suspect = False
        if cname:
            cname_suspect = any(p in cname for p in _CLOUD_CNAME_PATTERNS)

        # Étape 2 : Fingerprint HTTP
        vulnerable_service, evidence_text = _check_http_fingerprint(
            session, subdomain, cfg.http.timeout
        )

        entry: dict[str, object] = {
            "subdomain": subdomain,
            "cname": cname,
            "cname_suspect": cname_suspect,
            "vulnerable_service": vulnerable_service,
        }

        if vulnerable_service:
            log.info(
                f"  [red]TAKEOVER POSSIBLE[/] : {subdomain} "
                f"→ CNAME={cname} → service non réclamé : {vulnerable_service}"
            )
            report.add_finding(
                module="vuln.subdomain_takeover",
                severity=Severity.CRITICAL,
                title=f"Opportunité de takeover : {subdomain} ({vulnerable_service})",
                detail=(
                    f"Le sous-domaine {subdomain} pointe via CNAME vers {cname or 'inconnu'} "
                    f"mais la ressource {vulnerable_service} n'est plus réclamée. "
                    "Un attaquant peut enregistrer cette ressource et prendre le contrôle du sous-domaine."
                ),
                evidence={
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": vulnerable_service,
                    "response_excerpt": evidence_text,
                },
                references=[
                    "https://github.com/EdOverflow/can-i-take-over-xyz",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Cloud_Storage",
                ],
            )
        elif cname_suspect:
            log.info(f"  [yellow]CNAME suspect[/] : {subdomain} → {cname} (vérification manuelle recommandée)")
            report.add_finding(
                module="vuln.subdomain_takeover",
                severity=Severity.MEDIUM,
                title=f"Sous-domaine avec CNAME cloud — vérification requise : {subdomain}",
                detail=(
                    f"Le sous-domaine {subdomain} pointe via CNAME vers {cname} "
                    "(service cloud connu). Aucun fingerprint de takeover confirmé, "
                    "mais une vérification manuelle est recommandée."
                ),
                evidence={"subdomain": subdomain, "cname": cname},
                references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
            )
        else:
            log.debug(f"  {subdomain}: aucun indicateur de takeover")

        results.append(entry)

    takeover_count = sum(1 for r in results if r.get("vulnerable_service"))
    log.info(
        f"  {takeover_count} opportunité(s) de takeover détectée(s) "
        f"sur {len(results)} sous-domaines."
    )

    return results
