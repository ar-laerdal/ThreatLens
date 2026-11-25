"""Interactive threat table with filters and a per-threat detail view."""
import pandas as pd
import streamlit as st

from core import risk_engine
from core.schemas import STRIDE_VALUES, ThreatModel
from dashboard.common import SEV_ICON, STATUSES, by_threat, render_review_progress, review_counts


def _table(threats, links) -> pd.DataFrame:
    rows = []
    for t in threats:
        n = links[t.id]
        row = {"ID": t.id, "Severity": f"{SEV_ICON[t.severity]} {t.severity}", "Title": t.title,
               "Component": t.affected_component, "STRIDE": t.stride_category, "Score": t.risk_score,
               "Likelihood": t.likelihood, "Impact": t.impact, "Controls": len(n["controls"]),
               "Tests": len(n["tests"]), "Confidence": t.confidence, "Review": t.review_status}
        rows.append(row)
    return pd.DataFrame(rows)


def _bulk_set(ids: list[str], status: str, model: ThreatModel) -> None:
    """Callback: set the review status of several threats (and their detail widgets) at once."""
    for t in model.threats:
        if t.id in ids:
            t.review_status = status
            st.session_state[f"review_{t.id}"] = status


def render_detail(model: ThreatModel, threat_id: str) -> None:
    t = model.threat_by_id(threat_id)
    if t is None:
        return
    color = risk_engine.SEVERITY_COLORS[t.severity]
    st.markdown(f"### {t.id} - {t.title}")
    st.markdown(
        f"<span style='color:{color};font-weight:700'>{t.severity}</span> &nbsp;|&nbsp; score {t.risk_score} "
        + (
            f"(likelihood {t.likelihood} {risk_engine.LIKELIHOOD_LABELS[t.likelihood]} x impact {t.impact} "
            f"{risk_engine.IMPACT_LABELS[t.impact]})"
        ),
        unsafe_allow_html=True,
    )
    if not t.grounded:
        st.warning("The affected component was not found in the extracted architecture. Treat with caution.")
    a, b = st.columns(2)
    a.markdown(f"**Component:** {t.affected_component}\n\n**STRIDE:** {t.stride_category}\n\n**Confidence:** {t.confidence}")
    new_status = b.selectbox(
        "Human review status", ["Unreviewed", "Confirmed", "Rejected"],
        index=["Unreviewed", "Confirmed", "Rejected"].index(t.review_status), key=f"review_{t.id}",
    )
    if new_status != t.review_status:
        t.review_status = new_status
    st.markdown(f"**Description**\n\n{t.description}")
    st.markdown(f"**Attack scenario**\n\n{t.attack_scenario}")
    st.markdown(f"**Potential impact**\n\n{t.potential_impact}")
    st.markdown(f"**Evidence from the architecture**\n\n{t.evidence or '_none provided_'}")

    n = by_threat(model)[t.id]
    controls, cases, tests = n["controls"], n["cases"], n["tests"]
    with st.expander(f"Recommended controls ({len(controls)})", expanded=bool(controls)):
        for c in controls:
            st.markdown(f"**{c.control}** · priority {c.priority}")
            st.markdown(f"{c.implementation}")
            st.caption("References: " + "; ".join(f"{r.framework} {r.reference}" for r in c.framework_refs)
                       + f"  |  {c.status}")
    with st.expander(f"Related abuse cases ({len(cases)})"):
        for c in cases:
            st.markdown(f"**{c.id} {c.title}** · {c.attacker_profile}")
            st.markdown(c.scenario)
            st.caption("Prevention: " + "; ".join(c.prevention_measures[:3]))
    with st.expander(f"Security tests ({len(tests)})"):
        for x in tests:
            st.markdown(f"**{x.id}** · {x.objective}")
            st.markdown("\n".join(f"{i}. {step}" for i, step in enumerate(x.procedure, 1)))
            st.caption(f"Pass: {x.pass_criteria}  |  Fail: {x.fail_criteria}")


def render(model: ThreatModel) -> None:
    st.title("Threat Analysis")
    st.caption(risk_engine.METHODOLOGY)
    render_review_progress(model)

    c1, c2, c3, c4 = st.columns(4)
    severity = c1.multiselect("Severity", risk_engine.SEVERITIES)
    component = c2.multiselect("Component", sorted({t.affected_component for t in model.threats}))
    stride = c3.multiselect("STRIDE category", STRIDE_VALUES)
    status = c4.multiselect("Review status", STATUSES)
    query = st.text_input("Search title / description")

    shown = [
        t for t in model.threats
        if (not severity or t.severity in severity)
        and (not component or t.affected_component in component)
        and (not stride or t.stride_category in stride)
        and (not status or t.review_status in status)
        and (not query or query.lower() in f"{t.title} {t.description}".lower())
    ]
    st.write(f"Showing **{len(shown)}** of {len(model.threats)} threats. Click a column header to sort; "
             "select a row for details.")
    if not shown:
        st.info("No threats match the filters.")
        return

    links = by_threat(model)
    table = _table(shown, links)
    event = st.dataframe(table, hide_index=True, on_select="rerun", selection_mode="single-row", key="threat_table",
                         width="stretch")

    ids = [t.id for t in shown]
    b1, b2, b3, b4 = st.columns([1, 1, 1, 1])
    b1.button(f"✔ Confirm {len(shown)} shown", on_click=_bulk_set, args=(ids, "Confirmed", model), width="stretch",
              help="Marks every threat currently listed as confirmed by a human reviewer.")
    b2.button(f"✖ Reject {len(shown)} shown", on_click=_bulk_set, args=(ids, "Rejected", model), width="stretch")
    b3.button("↺ Reset shown", on_click=_bulk_set, args=(ids, "Unreviewed", model), width="stretch")
    b4.download_button("⬇ CSV of shown", table.to_csv(index=False), "threats.csv", "text/csv", width="stretch")

    rows = event.selection.rows
    st.divider()
    if rows:
        render_detail(model, shown[rows[0]].id)
    else:
        st.info("Select a threat in the table to view its full analysis, controls, abuse cases and tests.")
