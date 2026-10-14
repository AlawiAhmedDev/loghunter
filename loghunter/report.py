"""Output formats: console text, JSON and a self-contained HTML report."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime

from .models import SEVERITY_ORDER, Alert
from .parsers import ParseStats

_COLORS = {"critical": "\033[1;41;97m", "high": "\033[1;31m",
           "medium": "\033[33m", "low": "\033[36m"}
_RESET = "\033[0m"


def _summary(alerts: list[Alert]) -> dict[str, int]:
    c = Counter(a.severity for a in alerts)
    return {s: c.get(s, 0) for s in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)}


def render_text(alerts: list[Alert], stats: ParseStats, color: bool = True) -> str:
    out = [
        "LogHunter - security log analysis",
        f"Files: {stats.files}   Lines: {stats.lines}   Parsed events: {stats.parsed}"
        f"   Skipped: {stats.skipped}",
        "Summary: " + "  ".join(f"{k}={v}" for k, v in _summary(alerts).items()),
        "",
    ]
    if not alerts:
        out.append("No suspicious activity detected.")
        return "\n".join(out)
    for a in alerts:
        sev = a.severity.upper().ljust(8)
        if color:
            sev = f"{_COLORS[a.severity]}{sev}{_RESET}"
        out.append(f"[{sev}] {a.rule}  ip={a.ip}")
        out.append(f"           {a.description}")
        out.append(f"           MITRE: {a.mitre}")
        out.append(f"           {a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%Y-%m-%d %H:%M:%S}")
        out.append("")
    return "\n".join(out)


def render_json(alerts: list[Alert], stats: ParseStats) -> str:
    return json.dumps({
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "stats": {"files": stats.files, "lines": stats.lines,
                  "parsed": stats.parsed, "skipped": stats.skipped,
                  "by_source": stats.by_source},
        "summary": _summary(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }, indent=2, ensure_ascii=False)


def render_html(alerts: list[Alert], stats: ParseStats) -> str:
    e = html.escape
    summary = _summary(alerts)
    cards = "".join(
        f'<div class="card {s}"><span>{n}</span>{s}</div>' for s, n in summary.items()
    )
    rows = []
    for i, a in enumerate(alerts):
        evidence = "\n".join(e(x) for x in a.evidence)
        rows.append(f"""
<tr>
  <td><span class="sev {a.severity}">{a.severity}</span></td>
  <td><code>{e(a.rule)}</code></td>
  <td><code>{e(a.ip)}</code></td>
  <td>{e(a.description)}<details><summary>Evidence</summary><pre>{evidence}</pre></details></td>
  <td>{e(a.mitre)}</td>
  <td class="nowrap">{a.first_seen:%Y-%m-%d %H:%M:%S}<br>{a.last_seen:%Y-%m-%d %H:%M:%S}</td>
</tr>""")
    body = "".join(rows) or '<tr><td colspan="6">No suspicious activity detected.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogHunter report</title>
<style>
:root {{ --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --line:#e2e1dc; --panel:#fff; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#161615; --fg:#ecebe6; --muted:#9d9c96; --line:#2e2e2b; --panel:#1f1f1d; }} }}
body {{ margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
  font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }}
main {{ max-width:1200px; margin:auto; }}
h1 {{ margin:0 0 4px; font-size:24px; }} .meta {{ color:var(--muted); margin-bottom:20px; }}
.cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:12px 18px; min-width:110px; text-transform:capitalize; color:var(--muted); }}
.card span {{ display:block; font-size:28px; font-weight:700; color:var(--fg); }}
.table-wrap {{ overflow-x:auto; background:var(--panel); border:1px solid var(--line); border-radius:8px; }}
table {{ border-collapse:collapse; width:100%; }}
th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ font-size:13px; color:var(--muted); font-weight:600; }}
.sev {{ padding:2px 8px; border-radius:4px; font-size:12px; font-weight:700; text-transform:uppercase; }}
.critical {{ border-left:4px solid #c62828; }} .high {{ border-left:4px solid #e65100; }}
.medium {{ border-left:4px solid #b28704; }} .low {{ border-left:4px solid #1565c0; }}
.sev.critical {{ background:#c62828; color:#fff; border:0; }} .sev.high {{ background:#e65100; color:#fff; border:0; }}
.sev.medium {{ background:#f9a825; color:#1d1d1b; border:0; }} .sev.low {{ background:#1565c0; color:#fff; border:0; }}
pre {{ white-space:pre-wrap; word-break:break-all; font-size:12px; color:var(--muted); }}
summary {{ cursor:pointer; color:var(--muted); font-size:13px; margin-top:4px; }}
.nowrap {{ white-space:nowrap; font-size:13px; }}
</style></head><body><main>
<h1>LogHunter report</h1>
<div class="meta">Generated {datetime.now():%Y-%m-%d %H:%M} &middot; {stats.files} file(s),
 {stats.lines} lines, {stats.parsed} events parsed</div>
<div class="cards">{cards}</div>
<div class="table-wrap"><table>
<thead><tr><th>Severity</th><th>Rule</th><th>Source IP</th><th>Details</th><th>MITRE ATT&amp;CK</th><th>Time (UTC)</th></tr></thead>
<tbody>{body}</tbody></table></div>
</main></body></html>
"""
