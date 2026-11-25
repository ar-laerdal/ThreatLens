"""Dashboard overview: project info, summary cards, risk charts, recent findings."""
from html import escape
from typing import Optional

import pandas as pd
import plotly.express as px
import streamlit as st

from core import risk_engine
from core.llm_factory import MODE_LABELS
from core.schemas import ThreatModel
from dashboard.common import SEV_ICON, by_threat, render_review_progress, short

CHART_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#E6EDF3",
    margin=dict(l=10, r=10, t=40, b=10), legend_title_text="",
)


def summary(model: ThreatModel) -> None:
    """What needs attention first: verdict, top risks and review progress."""
    counts = risk_engine.severity_counts(model.threats)
    crit, high = counts["Critical"], counts["High"]
    if crit:
        verdict = f"**{crit} critical and {high} high** threats should be reviewed first."
    elif high:
        verdict = f"No critical threats; **{high} high** threats should be reviewed first."
    else:
        verdict = "No critical or high threats were identified. Review the medium ones next."
    with st.container(border=True):
        st.markdown(f"#### Where to start\n{verdict}")
        links = by_threat(model)
        cols = st.columns(3)
        for col, t in zip(cols, model.threats[:3]):
            n = links[t.id]
            with col:
                st.markdown(f"{SEV_ICON[t.severity]} **{t.id} · {t.severity}** (score {t.risk_score})")
                st.markdown(short(t.title, 90))
                st.caption(f"{t.affected_component} · {len(n['controls'])} controls · {len(n['tests'])} tests")
        render_review_progress(model)
        flagged = sum(c.needs_review for c in model.architecture.components) + sum(
            f.needs_review for f in model.architecture.data_flows)
        if flagged:
            st.caption(f"⚠️ {flagged} architecture item(s) were inferred or uncertain. Check them on the "
                       "**Architecture Analysis** page.")


def details_card(model: ThreatModel) -> None:
    arch = model.architecture
    with st.container(border=True):
        a, b, c, d = st.columns(4)
        a.caption("Source"); a.write(model.source_filename or "-")
        b.caption("Analysis mode"); b.write(MODE_LABELS.get(model.analysis_mode, model.analysis_mode or "-"))
        c.caption("Model"); c.write(model.llm_model or "-")
        d.caption("Analyzed / duration"); d.write(f"{model.generated_at.replace('T', ' ')} / {model.ai_duration_seconds:.0f}s")
        e, f, g, h = st.columns(4)
        e.caption("Components"); e.write(len(arch.components))
        f.caption("Data flows"); f.write(len(arch.data_flows))
        g.caption("Trust boundaries"); g.write(len(arch.trust_boundaries))
        h.caption("Sensitive assets"); h.write(len(arch.sensitive_assets))


def severity_cards(model: ThreatModel) -> None:
    counts = risk_engine.severity_counts(model.threats)
    cols = st.columns(6)
    cols[0].metric("Components", len(model.architecture.components))
    cols[1].metric("Threats", len(model.threats))
    for col, sev in zip(cols[2:], risk_engine.SEVERITIES):
        col.markdown(
            f"<div class='sev-card' style='border-top:3px solid {risk_engine.SEVERITY_COLORS[sev]}'>"
            f"<div class='sev-label'>{sev}</div><div class='sev-value'>{counts[sev]}</div></div>",
            unsafe_allow_html=True,
        )


def charts(model: ThreatModel) -> None:
    left, right = st.columns(2)

    sev_df = pd.DataFrame(list(risk_engine.severity_counts(model.threats).items()), columns=["Severity", "Count"])
    fig = px.pie(sev_df, names="Severity", values="Count", hole=0.55, title="Risk distribution",
                 color="Severity", color_discrete_map=risk_engine.SEVERITY_COLORS,
                 category_orders={"Severity": risk_engine.SEVERITIES})
    fig.update_layout(**CHART_LAYOUT)
    left.plotly_chart(fig)

    stride_df = pd.DataFrame(list(risk_engine.stride_counts(model.threats).items()), columns=["STRIDE", "Threats"])
    fig = px.bar(stride_df, x="Threats", y="STRIDE", orientation="h", title="Threats by STRIDE category")
    fig.update_traces(marker_color="#00D4AA")
    fig.update_layout(**CHART_LAYOUT, yaxis=dict(autorange="reversed"))
    right.plotly_chart(fig)

    rows = [
        {"Component": comp, "Severity": sev_name, "Threats": n}
        for comp, buckets in risk_engine.component_risk(model.threats).items()
        for sev_name, n in buckets.items() if n
    ]
    if rows:
        fig = px.bar(pd.DataFrame(rows), x="Component", y="Threats", color="Severity",
                     title="Risk by component", color_discrete_map=risk_engine.SEVERITY_COLORS,
                     category_orders={"Severity": risk_engine.SEVERITIES})
        fig.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig)


def render(model: Optional[ThreatModel], after_title=None) -> None:
    st.title("ThreatLens Dashboard")
    if after_title is not None and model is not None:
        after_title()
    if model is None:
        st.info("No architecture analyzed yet. Go to **Upload Architecture** and analyze a file, "
                "or load the built-in e-commerce sample.")
        return

    st.subheader(model.project_name)
    st.warning("Generated analysis. Every threat and mitigation is an unverified hypothesis until a "
               "security engineer reviews it.")
    summary(model)
    details_card(model)

    severity_cards(model)
    charts(model)

    st.subheader("Top findings by risk")
    links = by_threat(model)
    for t in model.threats[:5]:
        color = risk_engine.SEVERITY_COLORS[t.severity]
        n = links[t.id]
        st.markdown(
            f"<div class='finding' style='border-left:4px solid {color}'>"
            f"<b>{escape(t.id)}</b> &middot; {escape(t.title)} <span style='color:{color}'>[{t.severity}]</span><br>"
            f"<small>{escape(t.affected_component)} &middot; {escape(t.stride_category or 'threat')} &middot; "
            f"score {t.risk_score} &middot; {len(n['controls'])} controls &middot; {len(n['tests'])} tests</small><br>"
            f"<small style='color:#8B98A9'>{escape(short(t.potential_impact))}</small></div>",
            unsafe_allow_html=True,
        )
    st.caption("Open **Threat Analysis** in the sidebar for all threats, filters and the review workflow.")
    if model.warnings:
        with st.expander(f"Pipeline warnings ({len(model.warnings)})"):
            for w in model.warnings:
                st.write(f"- {w}")
