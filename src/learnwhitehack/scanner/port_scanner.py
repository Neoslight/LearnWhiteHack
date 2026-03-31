"""Scanner de ports TCP multi-threadé avec ordre de scan aléatoire."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import BarColumn, Progress, TaskProgressColumn, TimeRemainingColumn

from learnwhitehack.core.config import AppConfig
from learnwhitehack.core.logger import get_logger
from learnwhitehack.core.rate_limiter import shuffle_ports
from learnwhitehack.core.reporter import Report, Severity

log = get_logger("scanner.ports")


def _scan_port(ip: str, port: int, timeout: float = 1.0) -> tuple[int, bool]:
    """Tente une connexion TCP sur ip:port. Retourne (port, is_open)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return port, result == 0
    except Exception:
        return port, False


def run(cfg: AppConfig, report: Report) -> list[int]:
    """Scanne les ports TCP de la cible et retourne la liste des ports ouverts."""
    ip = cfg.target.ip
    if not ip:
        log.error("Aucune IP cible configurée (target.ip).")
        return []

    ports = shuffle_ports(cfg.scan.port_list())  # ordre aléatoire
    threads = cfg.scan.threads
    log.info(
        f"[bold]scanner.ports[/] → {ip} "
        f"({len(ports)} ports, {threads} threads, ordre aléatoire)"
    )

    open_ports: list[int] = []
    start = time.monotonic()

    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]Scan {ip}[/]", total=len(ports))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(_scan_port, ip, p, 1.0): p for p in ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                progress.advance(task)
                if is_open:
                    open_ports.append(port)
                    log.info(f"  [green]OUVERT[/] : {ip}:{port}")

    elapsed = time.monotonic() - start
    open_ports.sort()
    log.info(f"  Scan terminé en {elapsed:.1f}s — {len(open_ports)} port(s) ouvert(s)")

    if open_ports:
        report.add_finding(
            module="scanner.ports",
            severity=Severity.INFO,
            title=f"{len(open_ports)} port(s) TCP ouvert(s) sur {ip}",
            detail=f"Ports ouverts détectés : {', '.join(str(p) for p in open_ports)}",
            evidence={
                "ip": ip,
                "open_ports": open_ports,
                "scan_duration_sec": round(elapsed, 2),
                "port_range": cfg.scan.port_range,
            },
        )
    else:
        log.info(f"  Aucun port ouvert détecté sur {ip}")

    return open_ports
