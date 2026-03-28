"""Export d'un rapport JSON en HTML standalone avec tableaux filtrables."""

from __future__ import annotations

import json
from pathlib import Path


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport {target} — learnwhitehack</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          margin: 0; background: #0d1117; color: #c9d1d9; }}
  .header {{ background: #161b22; padding: 24px 32px; border-bottom: 1px solid #30363d; }}
  h1 {{ margin: 0; font-size: 1.5rem; }}
  .meta {{ font-size: 0.85rem; color: #8b949e; margin-top: 8px; }}
  .container {{ padding: 24px 32px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .badge {{ padding: 8px 16px; border-radius: 6px; font-weight: 600; font-size: 0.9rem; }}
  .CRITICAL {{ background: #6e1010; color: #ffa0a0; }}
  .HIGH     {{ background: #5a1e00; color: #ffb380; }}
  .MEDIUM   {{ background: #4a3800; color: #ffe080; }}
  .LOW      {{ background: #1a3a1a; color: #80e080; }}
  .INFO     {{ background: #1a2a3a; color: #80c0ff; }}
  .filters {{ margin-bottom: 16px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 6px 14px; border: 1px solid #30363d; border-radius: 20px;
                 background: transparent; color: #c9d1d9; cursor: pointer; }}
  .filter-btn.active {{ background: #388bfd22; border-color: #388bfd; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 10px 12px; background: #161b22;
        border-bottom: 2px solid #30363d; color: #8b949e; font-weight: 500; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #161b22; }}
  .sev {{ padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.78rem; white-space: nowrap; }}
  .detail-toggle {{ cursor: pointer; color: #388bfd; font-size: 0.8rem; }}
  .detail-row {{ display: none; }}
  .detail-row td {{ padding: 8px 12px 16px; color: #8b949e; }}
  pre {{ background: #0d1117; padding: 12px; border-radius: 6px; overflow: auto;
         font-size: 0.78rem; border: 1px solid #30363d; max-height: 300px; }}
  input#search {{ background: #161b22; border: 1px solid #30363d; color: #c9d1d9;
                  padding: 8px 12px; border-radius: 6px; width: 300px; font-size: 0.9rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>Rapport learnwhitehack</h1>
  <div class="meta">
    Cible : <strong>{target}</strong> &nbsp;|&nbsp;
    Run ID : <code>{run_id}</code> &nbsp;|&nbsp;
    {started_at}
  </div>
</div>
<div class="container">
  <div class="summary">{summary_badges}</div>
  <div class="filters">
    <input id="search" type="text" placeholder="Filtrer par titre, module..." oninput="applyFilter()">
    &nbsp;
    {filter_buttons}
  </div>
  <table id="findings-table">
    <thead><tr>
      <th style="width:90px">Sévérité</th>
      <th style="width:160px">Module</th>
      <th>Titre</th>
      <th style="width:80px">Détails</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<script>
function toggleDetail(id) {{
  var row = document.getElementById('detail-' + id);
  row.style.display = row.style.display === 'table-row' ? 'none' : 'table-row';
}}
function applyFilter() {{
  var q = document.getElementById('search').value.toLowerCase();
  var activeSevs = Array.from(document.querySelectorAll('.filter-btn.active')).map(b => b.dataset.sev);
  document.querySelectorAll('tr.finding-row').forEach(function(row) {{
    var title = row.dataset.title || '';
    var module = row.dataset.module || '';
    var sev = row.dataset.sev || '';
    var textMatch = !q || title.includes(q) || module.includes(q);
    var sevMatch = activeSevs.length === 0 || activeSevs.includes(sev);
    var detailRow = document.getElementById('detail-' + row.dataset.id);
    row.style.display = textMatch && sevMatch ? '' : 'none';
    if (detailRow) detailRow.style.display = 'none';
  }});
}}
function toggleSev(btn) {{
  btn.classList.toggle('active');
  applyFilter();
}}
</script>
</body>
</html>"""


def _sev_color(sev: str) -> str:
    colors = {
        "CRITICAL": "#6e1010",
        "HIGH": "#5a1e00",
        "MEDIUM": "#4a3800",
        "LOW": "#1a3a1a",
        "INFO": "#1a2a3a",
    }
    return colors.get(sev, "#333")


def export(report_path: Path, output_path: Path | None = None) -> Path:
    """Exporte un rapport JSON en HTML standalone."""
    data = json.loads(report_path.read_text(encoding="utf-8"))
    meta = data.get("meta", {})
    target = meta.get("target", {}).get("url", "") or meta.get("target", {}).get("ip", "")
    run_id = meta.get("run_id", "")
    started_at = meta.get("started_at", "")
    summary = data.get("summary", {}).get("by_severity", {})
    findings = data.get("findings", [])

    # Badges résumé
    badges = ""
    for sev, count in summary.items():
        if count:
            badges += f'<div class="badge {sev}">{sev}: {count}</div>'

    # Boutons filtres
    filter_btns = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if summary.get(sev, 0) > 0:
            filter_btns += f'<button class="filter-btn" data-sev="{sev}" onclick="toggleSev(this)">{sev}</button>'

    # Lignes tableau
    rows = ""
    for i, f in enumerate(findings):
        sev = f.get("severity", "INFO")
        title = f.get("title", "")
        module = f.get("module", "")
        detail = f.get("detail", "")
        evidence = json.dumps(f.get("evidence", {}), indent=2, ensure_ascii=False)
        fid = str(i)

        rows += f"""<tr class="finding-row" data-id="{fid}" data-title="{title.lower()}" data-module="{module}" data-sev="{sev}">
  <td><span class="sev {sev}" style="background:{_sev_color(sev)}">{sev}</span></td>
  <td><code style="font-size:0.78rem">{module}</code></td>
  <td>{title}</td>
  <td><span class="detail-toggle" onclick="toggleDetail('{fid}')">▶ voir</span></td>
</tr>
<tr class="detail-row" id="detail-{fid}"><td colspan="4">
  <strong>Détail :</strong> {detail}<br><br>
  <strong>Evidence :</strong><pre>{evidence}</pre>
</td></tr>"""

    html = _HTML_TEMPLATE.format(
        target=target,
        run_id=run_id,
        started_at=started_at,
        summary_badges=badges,
        filter_buttons=filter_btns,
        rows=rows,
    )

    out = output_path or report_path.with_suffix(".html")
    out.write_text(html, encoding="utf-8")
    print(f"Rapport HTML exporté : {out}")
    return out
