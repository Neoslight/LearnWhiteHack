"""Comparaison de deux rapports JSON — met en évidence les nouveaux findings."""

from __future__ import annotations

import json
from pathlib import Path


def diff(report_before: Path, report_after: Path) -> dict[str, object]:
    """Compare deux rapports et retourne les findings nouveaux, résolus et communs."""
    before = json.loads(report_before.read_text(encoding="utf-8"))
    after = json.loads(report_after.read_text(encoding="utf-8"))

    def finding_key(f: dict[str, object]) -> str:
        return f"{f['module']}::{f['title']}"

    before_keys = {finding_key(f): f for f in before.get("findings", [])}
    after_keys = {finding_key(f): f for f in after.get("findings", [])}

    new_findings = [f for k, f in after_keys.items() if k not in before_keys]
    resolved = [f for k, f in before_keys.items() if k not in after_keys]
    common = [f for k, f in after_keys.items() if k in before_keys]

    result = {
        "before": str(report_before),
        "after": str(report_after),
        "new_findings": new_findings,
        "resolved_findings": resolved,
        "persistent_findings": common,
        "summary": {
            "new": len(new_findings),
            "resolved": len(resolved),
            "persistent": len(common),
        },
    }

    # Affichage console
    print(f"\n=== Diff Rapport ===")
    print(f"  Nouveaux    : {len(new_findings)}")
    print(f"  Résolus     : {len(resolved)}")
    print(f"  Persistants : {len(common)}")
    if new_findings:
        print("\n  [NOUVEAUX]")
        for f in new_findings:
            print(f"    [{f['severity']}] {f['title']}")

    return result
