"""Dashboard-style building blocks for the detection view (cards, pills, gauge, charts).

Pure presentation: everything here takes plain dicts from the API and returns HTML or Plotly figures.
"""
from __future__ import annotations

from html import escape
from typing import Any

import plotly.graph_objects as go

LEVELS = ["critical", "high", "medium", "low", "info"]
COLORS = {"critical": "#b91c1c", "high": "#f97316", "medium": "#facc15", "low": "#60a5fa", "info": "#9ca3af"}
PILL_TEXT = {"critical": "#ffffff", "high": "#ffffff", "medium": "#713f12", "low": "#ffffff", "info": "#ffffff"}
# weight of one finding in the overall score
WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}

CSS = """
<style>
.ssc-card {background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:16px 18px; margin-bottom:12px;}
.ssc-card h4 {margin:0 0 10px 0; font-size:0.95rem; color:#111827;}
.ssc-kv {display:flex; justify-content:space-between; padding:5px 0; font-size:0.85rem; border-bottom:1px solid #f3f4f6;}
.ssc-kv span:first-child {color:#6b7280;}
.ssc-kv span:last-child {color:#111827; font-weight:600; text-align:right;}
.ssc-pill {display:inline-block; padding:2px 10px; border-radius:999px; font-size:0.7rem; font-weight:700;
           letter-spacing:.04em; text-transform:uppercase; white-space:nowrap;}
.ssc-score {background:linear-gradient(135deg,#2563eb,#4f46e5); color:#fff; border-radius:12px; padding:16px 18px; margin-bottom:12px;}
.ssc-score .big {font-size:2.2rem; font-weight:700; line-height:1;}
.ssc-score .lbl {font-size:0.8rem; opacity:.85; margin-top:6px;}
.ssc-bar {height:6px; background:rgba(255,255,255,.3); border-radius:4px; margin-top:10px;}
.ssc-bar > div {height:6px; background:#fff; border-radius:4px;}
.ssc-log {font-size:0.82rem; padding:7px 0; border-bottom:1px solid #f3f4f6; color:#374151;}
.ssc-log small {color:#9ca3af; display:block;}
table.ssc-table {width:100%; border-collapse:collapse; font-size:0.83rem;}
table.ssc-table th {text-align:left; color:#9ca3af; font-weight:600; font-size:0.72rem; text-transform:uppercase;
                    padding:8px 10px; border-bottom:1px solid #e5e7eb;}
table.ssc-table td {padding:9px 10px; border-bottom:1px solid #f3f4f6; color:#111827; vertical-align:middle;}
table.ssc-table tr:hover td {background:#f9fafb;}
</style>
"""


def pill(level: str) -> str:
    return (f"<span class='ssc-pill' style='background:{COLORS.get(level, '#9ca3af')};"
            f"color:{PILL_TEXT.get(level, '#fff')}'>{escape(level)}</span>")


def risk_score(by_risk: dict[str, int]) -> int:
    """0-100 heuristic: weighted count of findings, capped. Not a calibrated probability."""
    return min(100, sum(WEIGHT[k] * by_risk.get(k, 0) for k in LEVELS))


def score_band(score: int) -> tuple[str, str]:
    if score >= 70:
        return "Critical exposure", COLORS["critical"]
    if score >= 40:
        return "High exposure", COLORS["high"]
    if score >= 15:
        return "Moderate exposure", "#eab308"
    return "Low exposure", "#16a34a"


def gauge(score: int) -> go.Figure:
    label, color = score_band(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score, number=dict(suffix=" /100", font=dict(size=34)),
        gauge=dict(axis=dict(range=[0, 100], tickwidth=0, showticklabels=False), bar=dict(color=color, thickness=0.28),
                   bgcolor="#f3f4f6", borderwidth=0),
    ))
    fig.add_annotation(x=0.5, y=0.02, text=f"<b>{label}</b>", showarrow=False, font=dict(size=13, color=color))
    fig.update_layout(height=230, margin=dict(l=20, r=20, t=20, b=10), paper_bgcolor="rgba(0,0,0,0)")
    return fig


def _layer(f: dict[str, Any]) -> str:
    if f.get("dependency_type") in ("direct", "transitive"):
        return f["dependency_type"].capitalize() + " dependencies"
    return "Pipeline / images / config"


def layer_counts(findings: list[dict]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for f in findings:
        row = out.setdefault(_layer(f), {k: 0 for k in LEVELS})
        row[f["risk"]] += 1
    return out


def layer_chart(findings: list[dict]) -> go.Figure:
    """Findings per layer of the supply chain, stacked by risk level."""
    counts = layer_counts(findings)
    layers = sorted(counts, key=lambda k: -sum(counts[k].values()))
    fig = go.Figure()
    for lvl in LEVELS:
        vals = [counts[layer][lvl] for layer in layers]
        if any(vals):
            fig.add_bar(y=layers, x=vals, name=lvl.capitalize(), orientation="h", marker_color=COLORS[lvl],
                        hovertemplate="%{y}: %{x} " + lvl + "<extra></extra>")
    fig.update_layout(barmode="stack", height=230, margin=dict(l=10, r=10, t=10, b=10), plot_bgcolor="rgba(0,0,0,0)",
                      yaxis=dict(autorange="reversed"), xaxis=dict(showgrid=True, gridcolor="#f3f4f6", dtick=1),
                      legend=dict(orientation="h", y=-0.2))
    return fig


def rule_chart(findings: list[dict], labels: dict[str, str]) -> go.Figure:
    """What detected the findings (rule), most frequent first."""
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    items = sorted(by_rule.items(), key=lambda kv: -kv[1])[:8]
    fig = go.Figure(go.Bar(y=[labels.get(r, r) for r, _ in items], x=[n for _, n in items], orientation="h",
                           marker_color="#4f46e5", hovertemplate="%{y}: %{x}<extra></extra>"))
    fig.update_layout(height=max(160, 34 * len(items) + 40), margin=dict(l=10, r=10, t=10, b=10),
                      plot_bgcolor="rgba(0,0,0,0)", yaxis=dict(autorange="reversed"),
                      xaxis=dict(showgrid=True, gridcolor="#f3f4f6", dtick=1))
    return fig


def card(title: str, rows: list[tuple[str, str]]) -> str:
    body = "".join(f"<div class='ssc-kv'><span>{escape(k)}</span><span>{v}</span></div>" for k, v in rows)
    return f"<div class='ssc-card'><h4>{escape(title)}</h4>{body}</div>"


def score_card(label: str, pct: int, caption: str) -> str:
    return (f"<div class='ssc-score'><div class='big'>{pct}%</div><div class='lbl'>{escape(label)}</div>"
            f"<div class='ssc-bar'><div style='width:{pct}%'></div></div>"
            f"<div class='lbl' style='font-size:.72rem'>{escape(caption)}</div></div>")


def findings_table(rows: list[dict], labels: dict[str, str], limit: int = 60) -> str:
    head = ("<tr><th>Component</th><th>Detected by</th><th>Finding</th><th>Severity</th><th>Initial risk</th>"
            "<th>Fix</th></tr>")
    body = []
    for f in rows[:limit]:
        comp = escape(f"{f.get('component_name') or '—'} {f.get('component_version') or ''}".strip())
        fix = escape(", ".join(f["fixed_versions"][:2]) or ("none yet" if f["category"] == "vulnerability" else ""))
        title = escape(f["title"][:90] + ("…" if len(f["title"]) > 90 else ""))
        body.append(f"<tr><td><b>{comp}</b></td><td>{escape(labels.get(f['rule'], f['rule']))}</td><td>{title}</td>"
                    f"<td>{escape(str(f['severity']))}</td><td>{pill(f['risk'])}</td><td>{fix}</td></tr>")
    return f"<div class='ssc-card' style='padding:6px 10px'><table class='ssc-table'>{head}{''.join(body)}</table></div>"
