"""Recherche de CVEs dans la base NVD (NIST National Vulnerability Database)."""

from __future__ import annotations

import time

import requests

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("vuln.cve_search")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_DELAY = 6.0  # secondes entre requêtes (limite anonyme NVD)
_NVD_DELAY_WITH_KEY = 0.6  # avec clé API


def _cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def search(
    keyword: str,
    cfg: AppConfig,
    report: Report,
    max_results: int | None = None,
) -> list[dict[str, object]]:
    """Recherche des CVEs pour un keyword dans NVD et les ajoute au rapport."""
    max_r = max_results or cfg.nvd.max_results
    api_key = cfg.nvd.api_key
    delay = _NVD_DELAY_WITH_KEY if api_key else _NVD_DELAY

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    params: dict[str, object] = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max_r, 20),
    }

    log.info(f"[bold]vuln.cve_search[/] → '{keyword}' (NVD, max={max_r})")

    try:
        resp = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=15,
        )
    except Exception as e:
        log.error(f"Erreur NVD API: {e}")
        return []

    if resp.status_code == 429:
        log.warning("Rate-limit NVD atteint. Réessayer plus tard ou utiliser une clé API.")
        return []
    if resp.status_code == 403:
        log.warning(f"NVD API a retourné 403. Vérifier la clé API si configurée.")
        return []
    if resp.status_code != 200:
        log.error(f"NVD API erreur HTTP {resp.status_code}")
        return []

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    results: list[dict[str, object]] = []

    for item in vulnerabilities[:max_r]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        # Description anglaise
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "Pas de description disponible.",
        )

        # Score CVSS
        score: float | None = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score_data = metrics[key][0].get("cvssData", {})
                score = score_data.get("baseScore")
                break

        severity = _cvss_to_severity(score)
        log.info(f"  [{severity.value}] {cve_id} (score={score}) : {description[:80]}…")

        result = {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": score,
            "severity": severity.value,
            "references": [
                r.get("url", "") for r in cve.get("references", [])[:3]
            ],
        }
        results.append(result)

        report.add_finding(
            module="vuln.cve_search",
            severity=severity,
            title=f"{cve_id} — {description[:80]}",
            detail=description,
            evidence={
                "keyword": keyword,
                "cve_id": cve_id,
                "cvss_score": score,
            },
            references=result["references"],  # type: ignore[arg-type]
        )

    time.sleep(delay)  # respect NVD rate-limit
    return results


def run(cfg: AppConfig, report: Report, keywords: list[str] | None = None) -> None:
    """Lance la recherche CVE pour une liste de mots-clés."""
    default_keywords = ["wordpress", "nginx", "apache", "php"]
    kws = keywords or default_keywords

    for kw in kws:
        search(kw, cfg, report)
