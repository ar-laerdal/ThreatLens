"""Architecture analysis view: components, data flows, boundaries and a flow diagram."""
import re

import pandas as pd
import streamlit as st

from core.schemas import Architecture, ThreatModel

BOUNDARY_COLORS = {
    "External": "#FF4D6D", "DMZ": "#FF9F1C", "Internal": "#00D4AA", "Third-Party": "#B388FF", "Unknown": "#6B7280",
}


def _label(text: str) -> str:
    return re.sub(r'["\\\n]', " ", text)[:60]


def build_dot(arch: Architecture) -> str:
    """Graphviz DOT source; components are clustered by trust boundary, uncertain flows are dashed."""
    index = {c.name.strip().lower(): f"n{i}" for i, c in enumerate(arch.components)}
    lines = [
        "digraph G {", 'bgcolor="transparent"; rankdir=LR; compound=true;',
        'node [shape=box, style="rounded,filled", fillcolor="#111B2E", fontcolor="#E6EDF3", color="#00D4AA", fontsize=11];',
        'edge [color="#8B98A9", fontcolor="#C9D1D9", fontsize=9];',
    ]
    for boundary in dict.fromkeys(c.trust_boundary for c in arch.components):
        color = BOUNDARY_COLORS[boundary]
        lines.append(f'subgraph "cluster_{boundary}" {{ label="{boundary}"; fontcolor="{color}"; color="{color}"; style=dashed;')
        for c in arch.components:
            if c.trust_boundary == boundary:
                dashed = ',style="rounded,filled,dashed"' if c.needs_review else ""
                lines.append(f'{index[c.name.strip().lower()]} [label="{_label(c.name)}\\n({_label(c.type)})"{dashed}];')
        lines.append("}")
    for f in arch.data_flows:
        s, d = index.get(f.source.strip().lower()), index.get(f.destination.strip().lower())
        if s and d:
            style = ',style=dashed' if f.needs_review else ""
            lines.append(f'{s} -> {d} [label="{_label(f.data)}\\n{_label(f.protocol)}"{style}];')
    lines.append("}")
    return "\n".join(lines)


def render(model: ThreatModel) -> None:
    arch = model.architecture
    st.title("Architecture Analysis")
    st.warning("Extracted by AI. Items marked **inferred** or **needs review** are interpretations, not confirmed "
               "facts. Dashed shapes in the diagram are uncertain.")
    st.markdown(f"**{arch.system_name}**  \n{arch.summary}")

    st.subheader("Data flow diagram")
    st.graphviz_chart(build_dot(arch))

    st.subheader(f"Components ({len(arch.components)})")
    st.dataframe(
        pd.DataFrame([
            {"Name": c.name, "Type": c.type, "Trust boundary": c.trust_boundary, "Description": c.description,
             "Sensitive data": c.handles_sensitive_data, "Basis": c.basis, "Confidence": c.confidence,
             "Needs review": c.needs_review, "Evidence": c.evidence, "Review reason": c.review_reason}
            for c in arch.components
        ]), hide_index=True,
    )

    st.subheader(f"Data flows ({len(arch.data_flows)})")
    st.dataframe(
        pd.DataFrame([
            {"Source": f.source, "Destination": f.destination, "Data": f.data, "Protocol": f.protocol,
             "Authenticated": {True: "Yes", False: "No", None: "Unknown"}[f.authenticated],
             "Crosses boundary": f.crosses_trust_boundary, "Basis": f.basis, "Needs review": f.needs_review,
             "Review reason": f.review_reason}
            for f in arch.data_flows
        ]), hide_index=True,
    )

    left, right = st.columns(2)
    with left:
        st.subheader("Trust boundaries")
        for b in arch.trust_boundaries or []:
            st.markdown(f"- **{b.name}**: {b.description}")
        st.subheader("Sensitive assets")
        for a in arch.sensitive_assets or []:
            st.markdown(f"- **{a.name}** ({a.sensitivity}) {a.location}")
    with right:
        st.subheader("AI assumptions")
        for a in arch.assumptions or ["None recorded"]:
            st.markdown(f"- {a}")
        st.subheader("Open questions")
        for q in arch.open_questions or ["None recorded"]:
            st.markdown(f"- {q}")

    with st.expander("Raw architecture JSON"):
        st.json(arch.model_dump())
