"""Détection de la stack technique via headers, cookies et patterns HTML."""

from __future__ import annotations

import re

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("scanner.tech_fingerprint")

# (pattern_regex, technologie, sévérité_si_version_exposée)
_HTML_PATTERNS: list[tuple[str, str]] = [
    (r"wp-content",                         "WordPress"),
    (r"wp-includes",                        "WordPress"),
    (r"/themes/",                           "WordPress (theme)"),
    (r"Joomla",                             "Joomla"),
    (r"Drupal",                             "Drupal"),
    (r"Shopify\.theme",                     "Shopify"),
    (r"PrestaShop",                         "PrestaShop"),
    (r"Magento",                            "Magento"),
    (r"laravel_session",                    "Laravel"),
    (r"PHPSESSID",                          "PHP (session)"),
    (r"JSESSIONID",                         "Java (session)"),
    (r"ASP\.NET_SessionId",                 "ASP.NET"),
    (r"__cfduid|cf-ray",                    "Cloudflare"),
    (r"x-cache.*varnish",                   "Varnish Cache"),
    (r"x-powered-by.*express",              "Node.js Express"),
    (r"x-powered-by.*next\.js",             "Next.js"),
    (r"__next",                             "Next.js"),
    (r"react-root|__reactRoot",             "React"),
    (r"ng-version|angular",                 "Angular"),
    (r"vue-router|__vue",                   "Vue.js"),
    (r"woocommerce",                        "WooCommerce"),
    (r"elementor",                          "Elementor"),
    (r"yoast",                              "Yoast SEO"),
]

_HEADER_TECH: dict[str, str] = {
    "x-powered-by": "Stack (X-Powered-By)",
    "server": "Serveur Web",
    "x-generator": "Générateur",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-drupal-cache": "Drupal Cache",
    "x-wordpress-cache": "WordPress Cache",
}


def run(cfg: AppConfig, report: Report) -> dict[str, list[str]]:
    """Fingerprinte la stack technique de la cible."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return {}

    log.info(f"[bold]scanner.tech_fingerprint[/] → {base_url}")

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
        return {}

    technologies: set[str] = set()
    headers_info: dict[str, str] = {}

    # Headers révélateurs
    for header, label in _HEADER_TECH.items():
        val = resp.headers.get(header, "")
        if val:
            log.info(f"  [yellow]{label}[/] : {val}")
            technologies.add(f"{label}: {val}")
            headers_info[header] = val

    # Patterns HTML
    body_lower = resp.text.lower()
    for pattern, tech in _HTML_PATTERNS:
        if re.search(pattern, body_lower, re.IGNORECASE):
            if tech not in {t.split(":")[0] for t in technologies}:
                log.debug(f"  Pattern : {tech}")
                technologies.add(tech)

    # Cookies
    cookie_techs: list[str] = []
    for cookie in resp.cookies:
        for pattern, tech in _HTML_PATTERNS:
            if re.search(pattern, cookie.name, re.IGNORECASE):
                cookie_techs.append(f"{tech} (cookie: {cookie.name})")

    result: dict[str, list[str]] = {
        "technologies": sorted(technologies),
        "headers": [f"{k}: {v}" for k, v in headers_info.items()],
        "cookies": cookie_techs,
    }

    if technologies:
        log.info(f"  Technologies détectées : {sorted(technologies)}")
        report.add_finding(
            module="scanner.tech_fingerprint",
            severity=Severity.INFO,
            title=f"Stack technique identifiée ({len(technologies)} technologie(s))",
            detail="La stack technique a été identifiée via headers HTTP, cookies et patterns HTML.",
            evidence={
                "target": base_url,
                "technologies": sorted(technologies),
                "revealing_headers": headers_info,
            },
        )

    return result
