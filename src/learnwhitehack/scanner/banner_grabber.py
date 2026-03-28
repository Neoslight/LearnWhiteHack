"""Récupération de banners de services réseau (SSH, SMTP, HTTP, IMAP, etc.)."""

from __future__ import annotations

import socket
import ssl

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("scanner.banners")

# (port, use_ssl, probe)
# probe = bytes à envoyer pour obtenir une réponse
_DEFAULT_TARGETS: list[tuple[int, bool, bytes]] = [
    (21,   False, b""),                          # FTP
    (22,   False, b""),                          # SSH
    (25,   False, b"EHLO probe\r\n"),            # SMTP
    (80,   False, b"HEAD / HTTP/1.0\r\n\r\n"),  # HTTP
    (110,  False, b""),                          # POP3
    (143,  False, b""),                          # IMAP
    (443,  True,  b"HEAD / HTTP/1.0\r\n\r\n"),  # HTTPS
    (465,  True,  b""),                          # SMTPS
    (587,  False, b"EHLO probe\r\n"),            # SMTP submission
    (993,  True,  b""),                          # IMAPS
    (995,  True,  b""),                          # POP3S
    (3306, False, b""),                          # MySQL
    (3389, False, b""),                          # RDP
    (5432, False, b""),                          # PostgreSQL
    (6379, False, b"*1\r\n$4\r\nPING\r\n"),     # Redis
    (8080, False, b"HEAD / HTTP/1.0\r\n\r\n"),  # HTTP alt
    (8443, True,  b"HEAD / HTTP/1.0\r\n\r\n"),  # HTTPS alt
]


def _grab_banner(
    ip: str,
    port: int,
    use_ssl: bool,
    probe: bytes,
    timeout: int,
) -> str | None:
    """Tente de récupérer le banner d'un service. Retourne le banner ou None."""
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        raw.connect((ip, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn: socket.socket = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            conn = raw

        if probe:
            conn.sendall(probe)

        banner = conn.recv(4096).decode("utf-8", errors="replace").strip()
        conn.close()
        return banner if banner else None
    except Exception:
        return None


def run(
    cfg: AppConfig,
    report: Report,
    ports: list[int] | None = None,
) -> dict[int, str]:
    """Récupère les banners des services sur les ports spécifiés ou par défaut."""
    ip = cfg.target.ip
    if not ip:
        log.error("Aucune IP cible configurée (target.ip).")
        return {}

    # Si des ports sont passés, construire des cibles simplifiées
    if ports:
        targets: list[tuple[int, bool, bytes]] = []
        for p in ports:
            ssl_default = p in (443, 465, 993, 995, 8443)
            probe = b"HEAD / HTTP/1.0\r\n\r\n" if p in (80, 443, 8080, 8443) else b""
            targets.append((p, ssl_default, probe))
    else:
        targets = _DEFAULT_TARGETS

    log.info(f"[bold]scanner.banners[/] → {ip} ({len(targets)} ports)")

    results: dict[int, str] = {}
    for port, use_ssl, probe in targets:
        banner = _grab_banner(ip, port, use_ssl, probe, cfg.scan.banner_timeout)
        if banner:
            first_line = banner.split("\n")[0][:120]
            log.info(f"  [green]Port {port}[/] : {first_line}")
            results[port] = banner

            # Détection de versions sensibles
            severity = Severity.INFO
            lower = banner.lower()
            if any(s in lower for s in ["openssl/1.", "apache/2.2", "openssh_5", "openssh_6", "php/5."]):
                severity = Severity.HIGH
            elif any(s in lower for s in ["apache", "nginx", "php", "ssh", "smtp", "imap"]):
                severity = Severity.LOW

            report.add_finding(
                module="scanner.banners",
                severity=severity,
                title=f"Banner service port {port}",
                detail=f"Le service sur le port {port} expose des informations de version.",
                evidence={"ip": ip, "port": port, "ssl": use_ssl, "banner": banner[:500]},
            )
        else:
            log.debug(f"  Port {port} : pas de banner")

    return results
