"""Audit SSL/TLS : version, certificat, cipher suites, SAN."""

from __future__ import annotations

import datetime
import socket
import ssl
from urllib.parse import urlparse

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("recon.ssl_audit")

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHERS_SUBSTR = ["NULL", "EXPORT", "DES", "RC4", "MD5", "anon"]


def _get_cert_info(hostname: str, port: int = 443, timeout: int = 10) -> dict[str, object] | None:
    """Récupère les informations du certificat TLS."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                cert = s.getpeercert()
                cipher = s.cipher()
                protocol = s.version()
                return {
                    "cert": cert,
                    "cipher": cipher,
                    "protocol": protocol,
                }
    except Exception as e:
        log.debug(f"Erreur SSL {hostname}:{port}: {e}")
        return None


def run(cfg: AppConfig, report: Report) -> None:
    """Audite la configuration SSL/TLS de la cible."""
    url = cfg.target.url.rstrip("/")
    if not url:
        log.error("Aucune URL cible configurée.")
        return

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        report.add_finding(
            module="recon.ssl_audit",
            severity=Severity.HIGH,
            title="Site non HTTPS",
            detail="La cible n'utilise pas HTTPS. Les communications ne sont pas chiffrées.",
            evidence={"url": url},
        )
        return

    log.info(f"[bold]recon.ssl_audit[/] → {hostname}:{port}")

    info = _get_cert_info(hostname, port, cfg.http.timeout)
    if not info:
        log.warning(f"Impossible d'obtenir les infos TLS pour {hostname}:{port}")
        return

    cert = info["cert"]
    cipher_name, protocol, bits = info["cipher"] if info["cipher"] else (None, None, None)
    tls_version = info["protocol"]

    # Version TLS faible
    if tls_version in _WEAK_PROTOCOLS:
        log.info(f"  [red]Protocole faible[/] : {tls_version}")
        report.add_finding(
            module="recon.ssl_audit",
            severity=Severity.HIGH,
            title=f"Protocole TLS obsolète : {tls_version}",
            detail=f"Le serveur supporte {tls_version} qui est considéré comme vulnérable.",
            evidence={"hostname": hostname, "protocol": tls_version},
        )
    else:
        log.info(f"  Protocole TLS : {tls_version}")

    # Cipher suite faible
    if cipher_name:
        for weak in _WEAK_CIPHERS_SUBSTR:
            if weak in cipher_name.upper():
                report.add_finding(
                    module="recon.ssl_audit",
                    severity=Severity.HIGH,
                    title=f"Cipher suite faible : {cipher_name}",
                    detail=f"La suite de chiffrement {cipher_name} est considérée comme faible.",
                    evidence={"hostname": hostname, "cipher": cipher_name, "bits": bits},
                )
                break

    log.info(f"  Cipher : {cipher_name} ({bits} bits)")

    # Expiration du certificat
    if isinstance(cert, dict):
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.datetime.strptime(str(not_after), "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (exp - now).days

                if days_left < 0:
                    sev = Severity.CRITICAL
                    msg = f"Certificat EXPIRÉ depuis {abs(days_left)} jours"
                elif days_left < 14:
                    sev = Severity.HIGH
                    msg = f"Certificat expire dans {days_left} jours"
                elif days_left < 30:
                    sev = Severity.MEDIUM
                    msg = f"Certificat expire dans {days_left} jours"
                else:
                    sev = Severity.INFO
                    msg = f"Certificat valide ({days_left} jours restants)"

                log.info(f"  Certificat : {msg}")
                if sev != Severity.INFO:
                    report.add_finding(
                        module="recon.ssl_audit",
                        severity=sev,
                        title=msg,
                        detail=f"Le certificat TLS de {hostname} expire le {not_after}.",
                        evidence={"hostname": hostname, "expires": not_after, "days_left": days_left},
                    )
            except ValueError:
                pass

        # Extraction SAN
        san_list = cert.get("subjectAltName", [])
        domains = [v for (t, v) in san_list if t == "DNS"]
        if domains:
            log.info(f"  SAN (sous-domaines) : {domains}")
            report.add_finding(
                module="recon.ssl_audit",
                severity=Severity.INFO,
                title=f"SAN du certificat : {len(domains)} domaine(s)",
                detail="Les Subject Alternative Names révèlent les domaines couverts par ce certificat.",
                evidence={"hostname": hostname, "san_domains": domains},
            )

        # CN
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_org = issuer.get("organizationName", "")
        log.info(f"  CN={cn}, Issuer={issuer_org}")

        report.add_finding(
            module="recon.ssl_audit",
            severity=Severity.INFO,
            title=f"Informations certificat TLS",
            detail=f"CN={cn}, Issuer={issuer_org}, Protocol={tls_version}",
            evidence={
                "hostname": hostname,
                "common_name": cn,
                "issuer": issuer_org,
                "protocol": tls_version,
                "cipher": cipher_name,
                "bits": bits,
            },
        )
