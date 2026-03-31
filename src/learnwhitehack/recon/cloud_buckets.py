"""Détection de buckets cloud mal configurés (AWS S3, Azure Blob, GCP Storage)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.http_client import make_session
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.cloud_buckets")

_SUFFIXES = [
    "",
    "-dev",
    "-prod",
    "-staging",
    "-backup",
    "-data",
    "-assets",
    "-static",
    "-media",
    "-files",
    "-upload",
    "-images",
    "-public",
    "-private",
    "-internal",
    "-archive",
]

_PREFIXES = ["dev-", "backup-", "api-", "prod-", "staging-", "test-"]


def _extract_keyword(url: str) -> str:
    """Extrait le mot-clé de marque depuis une URL (ex: 'acme' depuis 'www.acme.com')."""
    hostname = urlparse(url).hostname or ""
    parts = hostname.split(".")
    # Ignorer le TLD (.fr, .com) et éventuellement le 'www'
    keyword = parts[-2] if len(parts) >= 2 else parts[0]
    # Nettoyer pour ne garder que les caractères valides dans un nom de bucket
    return re.sub(r"[^a-z0-9-]", "", keyword.lower())


def _make_bucket_names(keyword: str) -> list[str]:
    """Génère les permutations de noms de buckets à partir d'un mot-clé."""
    names: list[str] = []
    for suffix in _SUFFIXES:
        names.append(f"{keyword}{suffix}")
    for prefix in _PREFIXES:
        names.append(f"{prefix}{keyword}")
    return list(dict.fromkeys(names))  # dédoublonnage, ordre préservé


def _check_s3(session: object, bucket: str, timeout: int) -> dict[str, object] | None:
    """Teste un nom de bucket sur AWS S3."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)  # type: ignore[attr-defined]
        if resp.status_code == 200 and "ListBucketResult" in resp.text:
            return {
                "provider": "AWS S3",
                "bucket": bucket,
                "url": url,
                "status": "PUBLIC_LISTING",
                "http_status": 200,
                "file_count": resp.text.count("<Key>"),
            }
        if "NoSuchBucket" in resp.text or resp.status_code == 404:
            return None
        if resp.status_code in (200, 403, 405):
            label = "PUBLIC_ACCESS" if resp.status_code == 200 else "EXISTS_FORBIDDEN"
            return {
                "provider": "AWS S3",
                "bucket": bucket,
                "url": url,
                "status": label,
                "http_status": resp.status_code,
            }
    except Exception as exc:
        log.debug(f"S3 check error ({bucket}): {exc}")
    return None


def _check_azure(session: object, bucket: str, timeout: int) -> dict[str, object] | None:
    """Teste un nom de bucket sur Azure Blob Storage."""
    url = f"https://{bucket}.blob.core.windows.net/"
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)  # type: ignore[attr-defined]
        if resp.status_code == 404 and "ResourceNotFound" in resp.text:
            return None
        if resp.status_code in (200, 400, 403, 409):
            label = "PUBLIC_LISTING" if resp.status_code == 200 else "EXISTS"
            return {
                "provider": "Azure Blob",
                "bucket": bucket,
                "url": url,
                "status": label,
                "http_status": resp.status_code,
            }
    except Exception as exc:
        log.debug(f"Azure check error ({bucket}): {exc}")
    return None


def _check_gcp(session: object, bucket: str, timeout: int) -> dict[str, object] | None:
    """Teste un nom de bucket sur GCP Cloud Storage."""
    url = f"https://storage.googleapis.com/{bucket}/"
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)  # type: ignore[attr-defined]
        if resp.status_code == 200:
            return {
                "provider": "GCP Storage",
                "bucket": bucket,
                "url": url,
                "status": "PUBLIC_LISTING",
                "http_status": 200,
            }
        if resp.status_code == 403:
            return {
                "provider": "GCP Storage",
                "bucket": bucket,
                "url": url,
                "status": "EXISTS_FORBIDDEN",
                "http_status": 403,
            }
    except Exception as exc:
        log.debug(f"GCP check error ({bucket}): {exc}")
    return None


def run(cfg: AppConfig, report: Report) -> list[dict[str, object]]:
    """Détecte les buckets cloud exposés associés au domaine cible."""
    base_url = cfg.target.url.rstrip("/")
    if not base_url:
        log.error("Aucune URL cible configurée.")
        return []

    keyword = _extract_keyword(base_url)
    if not keyword:
        log.error("Impossible d'extraire un mot-clé depuis l'URL cible.")
        return []

    bucket_names = _make_bucket_names(keyword)
    log.info(
        f"[bold]recon.cloud_buckets[/] → {urlparse(base_url).hostname} "
        f"({len(bucket_names)} buckets × 3 providers)"
    )

    session = make_session(
        min_delay=cfg.stealth.min_delay,
        max_delay=cfg.stealth.max_delay,
        proxies=cfg.stealth.proxies,
        verify_ssl=cfg.http.verify_ssl,
    )

    results: list[dict[str, object]] = []

    for bucket in bucket_names:
        for checker in (_check_s3, _check_azure, _check_gcp):
            found = checker(session, bucket, cfg.http.timeout)
            if not found:
                continue

            results.append(found)
            status = found["status"]
            log.info(f"  [red]{status}[/] : {found['url']}")

            if status == "PUBLIC_LISTING":
                severity = Severity.CRITICAL
                title = f"Bucket cloud publiquement listable : {found['bucket']} ({found['provider']})"
                detail = (
                    f"Le bucket {found['provider']} '{found['bucket']}' est accessible publiquement "
                    f"à {found['url']} et permet de lister son contenu."
                )
            elif status == "PUBLIC_ACCESS":
                severity = Severity.HIGH
                title = f"Bucket cloud publiquement accessible : {found['bucket']} ({found['provider']})"
                detail = (
                    f"Le bucket {found['provider']} '{found['bucket']}' répond HTTP 200 "
                    f"à {found['url']} sans authentification."
                )
            else:  # EXISTS_FORBIDDEN ou EXISTS
                severity = Severity.MEDIUM
                title = f"Bucket cloud existant (accès refusé) : {found['bucket']} ({found['provider']})"
                detail = (
                    f"Le bucket {found['provider']} '{found['bucket']}' existe (HTTP {found['http_status']}) "
                    f"mais l'accès est restreint. Vérifier les ACL."
                )

            report.add_finding(
                module="recon.cloud_buckets",
                severity=severity,
                title=title,
                detail=detail,
                evidence=found,
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Cloud_Storage",
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html",
                    "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent",
                ],
            )

    if not results:
        log.info("  Aucun bucket cloud mal configuré trouvé.")

    return results
