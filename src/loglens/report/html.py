"""Self-contained, XSS-safe HTML report generator for LogLens."""

from __future__ import annotations

import html

from loglens.models import Report

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LogLens Triage Report - {safe_source}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --heading: #f0f6fc;
      --accent: #58a6ff;
      --sev-crit: #f85149;
      --sev-high: #ff7b72;
      --sev-med: #d29922;
      --sev-low: #388bfd;
      --sev-info: #8b949e;
    }}
    [data-theme="light"] {{
      --bg: #f6f8fa;
      --card-bg: #ffffff;
      --border: #d0d7de;
      --text: #24292f;
      --heading: #1f2328;
      --accent: #0969da;
      --sev-crit: #cf222e;
      --sev-high: #d1242f;
      --sev-med: #9a6700;
      --sev-low: #0969da;
      --sev-info: #57606a;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem 1rem;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }}
    h1 {{ color: var(--heading); font-size: 1.8rem; font-weight: 700; }}
    .theme-toggle {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2.5rem;
    }}
    .stat-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      text-align: center;
    }}
    .stat-val {{ font-size: 2rem; font-weight: 700; color: var(--heading); }}
    .stat-label {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; }}
    .section-title {{ color: var(--heading); margin-bottom: 1rem; font-size: 1.4rem; }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1.5rem;
      overflow: hidden;
      border-left: 6px solid var(--border);
    }}
    .finding-card.critical {{ border-left-color: var(--sev-crit); }}
    .finding-card.high {{ border-left-color: var(--sev-high); }}
    .finding-card.medium {{ border-left-color: var(--sev-med); }}
    .finding-card.low {{ border-left-color: var(--sev-low); }}
    .finding-card.info {{ border-left-color: var(--sev-info); }}
    .finding-header {{
      padding: 1rem 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
    }}
    .finding-body {{ padding: 1.25rem; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      color: #fff;
    }}
    .badge.critical {{ background: var(--sev-crit); }}
    .badge.high {{ background: var(--sev-high); }}
    .badge.medium {{ background: var(--sev-med); }}
    .badge.low {{ background: var(--sev-low); }}
    .badge.info {{ background: var(--sev-info); }}
    .finding-summary {{ font-size: 1.05rem; margin-bottom: 1rem; color: var(--heading); }}
    .list-block {{ margin: 0.75rem 0 1rem 1.5rem; }}
    .list-block li {{ margin-bottom: 0.35rem; }}
    .code-box {{
      background: rgba(0, 0, 0, 0.2);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.9em;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      font-size: 0.9rem;
    }}
    th, td {{
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{ background: rgba(255, 255, 255, 0.03); color: var(--heading); }}
    footer {{
      margin-top: 3rem;
      text-align: center;
      font-size: 0.8rem;
      opacity: 0.6;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>LogLens Security Triage</h1>
        <div style="font-size: 0.85rem; opacity: 0.7;">
          Source: <span class="code-box">{safe_source}</span> | Generated: {safe_date}
        </div>
      </div>
      <button class="theme-toggle" onclick="toggleTheme()">Toggle Theme</button>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val">{total_lines:,}</div>
        <div class="stat-label">Total Lines</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{parsed_events:,}</div>
        <div class="stat-label">Parsed Events</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{total_clusters:,}</div>
        <div class="stat-label">Mined Clusters</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: {finding_color};">{findings_count}</div>
        <div class="stat-label">Actionable Findings</div>
      </div>
    </div>

    <h2 class="section-title">Actionable Security Findings ({findings_count})</h2>
    {findings_html}

    <h2 class="section-title" style="margin-top: 2.5rem;">Top Mined Clusters</h2>
    <div style="background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Cluster ID</th>
            <th>Events</th>
            <th>Mined Template Pattern</th>
          </tr>
        </thead>
        <tbody>
          {clusters_table_html}
        </tbody>
      </table>
    </div>

    <footer>
      Generated with LogLens AI-Assisted Security Log Triage &bull; Schema v{safe_schema_ver}
    </footer>
  </div>

  <script>
    function toggleTheme() {{
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
    }}
  </script>
</body>
</html>
"""


def generate_html_report(report: Report) -> str:
    """Generate a self-contained, XSS-safe HTML report."""
    meta = report.metadata

    # 1. Escape all metadata strings
    safe_source = html.escape(meta.log_source)
    safe_date = html.escape(meta.generated_at.isoformat())
    safe_schema_ver = html.escape(meta.schema_version)

    finding_color = "var(--sev-crit)" if meta.findings_count > 0 else "var(--heading)"

    # 2. Render Findings (Strictly Escaping all user/log derived strings)
    sorted_findings = sorted(
        report.findings,
        key=lambda f: SEVERITY_ORDER.get(f.rule_severity, 1),
        reverse=True,
    )

    findings_parts: list[str] = []
    if sorted_findings:
        for f in sorted_findings:
            safe_id = html.escape(f.id)
            safe_sev = html.escape(f.rule_severity)
            rules_str = ", ".join(html.escape(r) for r in f.rule_ids) if f.rule_ids else "None"
            clusters_str = ", ".join(html.escape(c) for c in f.cluster_ids)

            card_html = [
                f'<div class="finding-card {safe_sev}">',
                '  <div class="finding-header">',
                f'    <div><strong>Finding {safe_id}</strong> &bull; Rules: <span class="code-box">{rules_str}</span></div>',
                f'    <span class="badge {safe_sev}">{safe_sev}</span>',
                "  </div>",
                '  <div class="finding-body">',
            ]

            if f.llm:
                safe_summary = html.escape(f.llm.summary)
                safe_attack = html.escape(f.llm.attack_type or "Unclassified")
                safe_fp = html.escape(f.llm.false_positive_likelihood)
                conf_pct = f"{f.llm.confidence * 100:.0f}%"

                card_html.append(f'    <div class="finding-summary">{safe_summary}</div>')
                card_html.append(
                    f'    <div style="font-size: 0.85rem; opacity: 0.8; margin-bottom: 0.75rem;">'
                    f"      Threat: <strong>{safe_attack}</strong> | "
                    f"      Confidence: <strong>{conf_pct}</strong> | "
                    f"      False Positive Risk: <strong>{safe_fp}</strong> | "
                    f'      Clusters: <span class="code-box">{clusters_str}</span>'
                    f"    </div>"
                )

                if f.llm.evidence:
                    card_html.append("    <p><strong>Observed Evidence:</strong></p>")
                    card_html.append('    <ul class="list-block">')
                    for ev in f.llm.evidence:
                        card_html.append(f"      <li>{html.escape(ev)}</li>")
                    card_html.append("    </ul>")

                if f.llm.recommended_actions:
                    card_html.append("    <p><strong>Recommended Actions:</strong></p>")
                    card_html.append('    <ul class="list-block">')
                    for act in f.llm.recommended_actions:
                        card_html.append(f"      <li>➜ {html.escape(act)}</li>")
                    card_html.append("    </ul>")
            else:
                card_html.append(
                    f'    <div class="finding-summary">Rule match triggered on cluster(s): {clusters_str}</div>'
                )

            card_html.append("  </div>")
            card_html.append("</div>")
            findings_parts.append("\n".join(card_html))
    else:
        findings_parts.append(
            '<div class="stat-card" style="text-align: left; padding: 1.5rem;">'
            "  <strong>All Clear:</strong> No security findings or anomalous rule violations detected."
            "</div>"
        )

    # 3. Render Clusters Table (Escaped)
    cluster_rows: list[str] = []
    for c in report.clusters[:15]:
        safe_c_id = html.escape(c.id)
        safe_tmpl = html.escape(c.template)
        cluster_rows.append(
            f'<tr><td><span class="code-box">{safe_c_id}</span></td><td>{c.count:,}</td><td><code>{safe_tmpl}</code></td></tr>'
        )

    return HTML_TEMPLATE.format(
        safe_source=safe_source,
        safe_date=safe_date,
        safe_schema_ver=safe_schema_ver,
        total_lines=meta.total_lines,
        parsed_events=meta.parsed_events,
        total_clusters=meta.total_clusters,
        findings_count=meta.findings_count,
        finding_color=finding_color,
        findings_html="\n".join(findings_parts),
        clusters_table_html="\n".join(cluster_rows)
        if cluster_rows
        else "<tr><td colspan='3'>None</td></tr>",
    )


class HTMLReportFormatter:
    """Renders Report into self-contained HTML."""

    def format(self, report: Report) -> str:
        return generate_html_report(report)
