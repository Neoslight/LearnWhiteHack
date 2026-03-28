"""Collecte et sérialisation des findings en JSON + Markdown."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    module: str
    severity: Severity
    title: str
    detail: str
    evidence: dict[str, object] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "references": self.references,
            "timestamp": self.timestamp,
        }


class Report:
    """Agrège les findings d'un run et les sérialise."""

    def __init__(self, target_url: str = "", target_ip: str = "") -> None:
        self._findings: list[Finding] = []
        self._target_url = target_url
        self._target_ip = target_ip
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._run_id = str(uuid.uuid4())
        self._modules_run: list[str] = []

    def add_finding(
        self,
        module: str,
        severity: Severity | str,
        title: str,
        detail: str,
        evidence: dict[str, object] | None = None,
        references: list[str] | None = None,
    ) -> Finding:
        if isinstance(severity, str):
            severity = Severity(severity.upper())
        f = Finding(
            module=module,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence or {},
            references=references or [],
        )
        self._findings.append(f)
        if module not in self._modules_run:
            self._modules_run.append(module)
        return f

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self._findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        finished = datetime.now(timezone.utc).isoformat()
        return {
            "meta": {
                "tool": "learnwhitehack",
                "version": "0.1.0",
                "run_id": self._run_id,
                "started_at": self._started_at,
                "finished_at": finished,
                "target": {
                    "url": self._target_url,
                    "ip": self._target_ip,
                },
                "modules_run": self._modules_run,
            },
            "summary": {
                "total_findings": len(self._findings),
                "by_severity": self.summary(),
            },
            "findings": [f.to_dict() for f in self._findings],
        }

    def save(self, output_dir: str = "reports", prefix: str = "") -> Path:
        """Sauvegarde le rapport JSON et retourne le chemin."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        hostname = _extract_hostname(self._target_url) or self._target_ip or "unknown"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        stem = f"{prefix or hostname}_{ts}"

        json_path = out / f"{stem}.json"
        json_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        md_path = out / f"{stem}.md"
        md_path.write_text(self._to_markdown(), encoding="utf-8")

        return json_path

    def _to_markdown(self) -> str:
        d = self.to_dict()
        meta = d["meta"]  # type: ignore[index]
        lines = [
            f"# Rapport learnwhitehack",
            f"",
            f"**Cible :** {meta['target']['url'] or meta['target']['ip']}",  # type: ignore[index]
            f"**Run ID :** `{meta['run_id']}`",  # type: ignore[index]
            f"**Date :** {meta['started_at']}",  # type: ignore[index]
            f"**Modules :** {', '.join(meta['modules_run'])}",  # type: ignore[index]
            f"",
            f"## Résumé",
            f"",
            f"| Sévérité | Nombre |",
            f"|---|---|",
        ]
        summary = d["summary"]["by_severity"]  # type: ignore[index]
        for sev, count in summary.items():  # type: ignore[union-attr]
            if count:
                lines.append(f"| {sev} | {count} |")
        lines += ["", "## Findings", ""]
        for f in d["findings"]:  # type: ignore[union-attr]
            lines += [
                f"### [{f['severity']}] {f['title']}",  # type: ignore[index]
                f"",
                f"**Module :** `{f['module']}`",  # type: ignore[index]
                f"",
                f"{f['detail']}",  # type: ignore[index]
                f"",
            ]
            if f["evidence"]:  # type: ignore[index]
                lines.append("**Preuve :**")
                lines.append("```json")
                lines.append(json.dumps(f["evidence"], indent=2, ensure_ascii=False))  # type: ignore[arg-type]
                lines.append("```")
                lines.append("")
        return "\n".join(lines)

    def print_summary(self) -> None:
        """Affiche un résumé console rapide."""
        s = self.summary()
        total = len(self._findings)
        print(f"\n=== Rapport : {total} finding(s) ===")
        for sev, count in s.items():
            if count:
                print(f"  {sev}: {count}")


def _extract_hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""
