"""Interactive Plotly chart generation for SOC Threat Reports."""
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional
import plotly.graph_objects as go
import plotly.io as pio

from ..models import Finding

# Dark SOC theme palette
SOC_THEME = {
    "bg_color": "rgba(22, 27, 34, 0.8)",
    "paper_color": "rgba(0,0,0,0)",
    "text_color": "#c9d1d9",
    "grid_color": "#30363d",
    "font_family": "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    "severity_colors": {
        "CRITICAL": "#f85149",
        "HIGH": "#da3633",
        "MEDIUM": "#d29922",
        "LOW": "#58a6ff",
    },
    "attack_palette": [
        "#f85149",
        "#58a6ff",
        "#3fb950",
        "#d29922",
        "#a371f7",
        "#f0883e",
        "#79c0ff",
    ],
}


def build_timeline_chart(findings: List[Finding]) -> str:
    """Generate interactive timeline chart of attacks over time."""
    if not findings:
        return "<div class='empty-chart'>No attack events to display in timeline.</div>"

    # Sort findings by timestamp
    sorted_findings = sorted(findings, key=lambda f: f.timestamp)
    
    # Bin by minute or second
    time_counts: Dict[str, Dict[str, int]] = {}
    for f in sorted_findings:
        bucket = f.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        if bucket not in time_counts:
            time_counts[bucket] = Counter()
        time_counts[bucket][f.attack_type] += 1

    buckets = list(time_counts.keys())
    attack_types = sorted(list({f.attack_type for f in sorted_findings}))

    fig = go.Figure()
    for idx, atype in enumerate(attack_types):
        counts = [time_counts[b].get(atype, 0) for b in buckets]
        color = SOC_THEME["attack_palette"][idx % len(SOC_THEME["attack_palette"])]
        fig.add_trace(
            go.Bar(
                x=buckets,
                y=counts,
                name=atype,
                marker=dict(color=color),
                hovertemplate="<b>%{x}</b><br>" + f"{atype}: %{{y}} events<extra></extra>",
            )
        )

    fig.update_layout(
        title=dict(text="Threat Events Over Time", font=dict(color=SOC_THEME["text_color"], size=15)),
        barmode="stack",
        paper_bgcolor=SOC_THEME["paper_color"],
        plot_bgcolor=SOC_THEME["paper_color"],
        font=dict(family=SOC_THEME["font_family"], color=SOC_THEME["text_color"]),
        xaxis=dict(
            title="Timestamp",
            gridcolor=SOC_THEME["grid_color"],
            showgrid=True,
            tickangle=-30,
        ),
        yaxis=dict(
            title="Event Count",
            gridcolor=SOC_THEME["grid_color"],
            showgrid=True,
            dtick=1,
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=11),
        ),
        margin=dict(l=40, r=20, t=50, b=50),
        height=320,
    )

    return pio.to_html(fig, full_html=False, include_plotlyjs=False, config={"displayModeBar": False, "responsive": True})


def build_attack_breakdown_chart(findings: List[Finding]) -> str:
    """Generate donut chart for attack category breakdown."""
    if not findings:
        return "<div class='empty-chart'>No findings recorded.</div>"

    type_counts = Counter(f.attack_type for f in findings)
    labels = list(type_counts.keys())
    values = list(type_counts.values())

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.55,
                marker=dict(colors=SOC_THEME["attack_palette"][:len(labels)]),
                textinfo="label+percent",
                hoverinfo="label+value+percent",
                hovertemplate="<b>%{label}</b><br>Findings: %{value} (%{percent})<extra></extra>",
            )
        ]
    )

    fig.update_layout(
        title=dict(text="Attack Vector Distribution", font=dict(color=SOC_THEME["text_color"], size=15)),
        paper_bgcolor=SOC_THEME["paper_color"],
        plot_bgcolor=SOC_THEME["paper_color"],
        font=dict(family=SOC_THEME["font_family"], color=SOC_THEME["text_color"]),
        showlegend=True,
        legend=dict(orientation="v", font=dict(size=11)),
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
    )

    return pio.to_html(fig, full_html=False, include_plotlyjs=False, config={"displayModeBar": False, "responsive": True})


def build_severity_chart(findings: List[Finding]) -> str:
    """Generate horizontal bar chart for severity breakdown."""
    if not findings:
        return "<div class='empty-chart'>No findings recorded.</div>"

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_counts = Counter(f.severity.upper() for f in findings)

    labels = [s for s in severities if sev_counts[s] > 0]
    values = [sev_counts[s] for s in labels]
    colors = [SOC_THEME["severity_colors"].get(s, "#58a6ff") for s in labels]

    fig = go.Figure(
        data=[
            go.Bar(
                x=values,
                y=labels,
                orientation="h",
                marker=dict(color=colors, line=dict(width=1, color="#30363d")),
                hovertemplate="<b>Severity: %{y}</b><br>Count: %{x}<extra></extra>",
            )
        ]
    )

    fig.update_layout(
        title=dict(text="Findings by Severity", font=dict(color=SOC_THEME["text_color"], size=15)),
        paper_bgcolor=SOC_THEME["paper_color"],
        plot_bgcolor=SOC_THEME["paper_color"],
        font=dict(family=SOC_THEME["font_family"], color=SOC_THEME["text_color"]),
        xaxis=dict(title="Findings Count", gridcolor=SOC_THEME["grid_color"], showgrid=True),
        yaxis=dict(autorange="reversed"),
        margin=dict(l=60, r=20, t=40, b=40),
        height=240,
    )

    return pio.to_html(fig, full_html=False, include_plotlyjs=False, config={"displayModeBar": False, "responsive": True})


def build_top_ips_chart(findings: List[Finding], top_n: int = 7) -> str:
    """Generate horizontal bar chart for top offending IP addresses."""
    if not findings:
        return "<div class='empty-chart'>No offending IPs recorded.</div>"

    ip_counts = Counter(f.ip for f in findings if f.ip).most_common(top_n)
    if not ip_counts:
        return "<div class='empty-chart'>No IP data available.</div>"

    ips = [item[0] for item in ip_counts]
    counts = [item[1] for item in ip_counts]

    fig = go.Figure(
        data=[
            go.Bar(
                x=counts,
                y=ips,
                orientation="h",
                marker=dict(
                    color="#f85149",
                    opacity=0.85,
                    line=dict(width=1, color="#f85149"),
                ),
                hovertemplate="<b>IP: %{y}</b><br>Threat Events: %{x}<extra></extra>",
            )
        ]
    )

    fig.update_layout(
        title=dict(text=f"Top {len(ips)} Malicious Sources", font=dict(color=SOC_THEME["text_color"], size=15)),
        paper_bgcolor=SOC_THEME["paper_color"],
        plot_bgcolor=SOC_THEME["paper_color"],
        font=dict(family=SOC_THEME["font_family"], color=SOC_THEME["text_color"]),
        xaxis=dict(title="Total Threat Events", gridcolor=SOC_THEME["grid_color"], showgrid=True),
        yaxis=dict(autorange="reversed"),
        margin=dict(l=100, r=20, t=40, b=40),
        height=240,
    )

    return pio.to_html(fig, full_html=False, include_plotlyjs=False, config={"displayModeBar": False, "responsive": True})
