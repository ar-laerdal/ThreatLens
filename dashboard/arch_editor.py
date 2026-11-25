"""Review and edit the detected architecture before threats are generated."""
import math
from typing import Optional

import pandas as pd
import streamlit as st

from core.knowledge import load_catalog
from core.schemas import BOUNDARY_VALUES, Architecture, Component, DataFlow

AUTH_CHOICES = ["Unknown", "Yes", "No"]
_AUTH_TO_VALUE = {"Yes": True, "No": False, "Unknown": None}
REVIEWED_NOTE = "Components and data flows were reviewed and edited by the user before analysis."


def _text(value) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return ""
    return str(value).strip()


def components_frame(arch: Architecture) -> pd.DataFrame:
    return pd.DataFrame([
        {"Name": c.name, "Type": c.type, "Trust boundary": c.trust_boundary,
         "Sensitive data": c.handles_sensitive_data, "Description": c.description}
        for c in arch.components
    ])


def flows_frame(arch: Architecture) -> pd.DataFrame:
    back = {True: "Yes", False: "No", None: "Unknown"}
    return pd.DataFrame([
        {"Source": f.source, "Destination": f.destination, "Protocol": f.protocol,
         "Authenticated": back[f.authenticated], "Data": f.data}
        for f in arch.data_flows
    ], columns=["Source", "Destination", "Protocol", "Authenticated", "Data"])


def build_architecture(original: Architecture, components: pd.DataFrame, flows: pd.DataFrame
                       ) -> tuple[Optional[Architecture], list[str]]:
    """Apply the edited tables to the architecture. Returns (architecture, errors); errors block the run."""
    errors: list[str] = []
    old_components = {c.name.lower(): c for c in original.components}
    old_flows = {(f.source.lower(), f.destination.lower()): f for f in original.data_flows}

    built: list[Component] = []
    seen: set[str] = set()
    for row in components.to_dict("records"):
        name = _text(row.get("Name"))
        if not name:
            continue
        if name.lower() in seen:
            errors.append(f"Duplicate component name: {name}.")
            continue
        seen.add(name.lower())
        boundary = _text(row.get("Trust boundary")) or "Unknown"
        base = old_components.get(name.lower())
        fields = dict(
            name=name, type=_text(row.get("Type")) or "Unknown", trust_boundary=boundary,
            handles_sensitive_data=bool(row.get("Sensitive data")), description=_text(row.get("Description")),
            basis="stated", confidence="High", needs_review=False, review_reason="",
        )
        if base is not None:
            built.append(base.model_copy(update={**fields, "evidence": f"Reviewed by user. {base.evidence}".strip()}))
        else:
            built.append(Component(**fields, evidence="Added by reviewer."))
    if not built:
        errors.append("At least one component is required.")

    boundaries = {c.name.lower(): c.trust_boundary for c in built}
    built_flows: list[DataFlow] = []
    seen_flows: set[tuple[str, str]] = set()
    for row in flows.to_dict("records"):
        src, dst = _text(row.get("Source")), _text(row.get("Destination"))
        if not src and not dst:
            continue
        missing = [n for n in (src, dst) if n.lower() not in boundaries]
        if missing:
            errors.append(f"Flow {src or '?'} -> {dst or '?'} refers to unknown component(s): {', '.join(missing) or '?'}.")
            continue
        key = (src.lower(), dst.lower())
        if key in seen_flows:
            continue
        seen_flows.add(key)
        base = old_flows.get(key)
        fields = dict(
            source=src, destination=dst, protocol=_text(row.get("Protocol")) or "Unspecified",
            data=_text(row.get("Data")), authenticated=_AUTH_TO_VALUE.get(_text(row.get("Authenticated")), None),
            crosses_trust_boundary=boundaries[src.lower()] != boundaries[dst.lower()],
            basis="stated", confidence="High", needs_review=False, review_reason="",
        )
        if base is not None:
            built_flows.append(base.model_copy(update={**fields, "evidence": f"Reviewed by user. {base.evidence}".strip()}))
        else:
            built_flows.append(DataFlow(**fields, evidence="Added by reviewer."))

    if errors:
        return None, errors
    names = {c.name for c in built}
    assets = [a for a in original.sensitive_assets if a.location in names or not a.location]
    assumptions = [a for a in original.assumptions if a != REVIEWED_NOTE] + [REVIEWED_NOTE]
    return original.model_copy(update={
        "components": built, "data_flows": built_flows, "sensitive_assets": assets, "assumptions": assumptions,
    }), []


def render(draft_id: str, arch: Architecture) -> Optional[Architecture]:
    """Show the editable tables. Returns the edited architecture when the user confirms, else None."""
    st.caption("Fix names, types and trust boundaries, remove false detections and add missing components or "
               "connections. The threat analysis uses exactly what is below.")
    type_options = sorted({e["name"] for e in load_catalog()["types"].values()} | {c.type for c in arch.components}
                          | {"Unknown"})
    st.markdown("**Components**")
    comps = st.data_editor(
        components_frame(arch), num_rows="dynamic", hide_index=True, key=f"ed_components_{draft_id}",
        width="stretch",
        column_config={
            "Name": st.column_config.TextColumn(required=True),
            "Type": st.column_config.SelectboxColumn(options=type_options, required=True),
            "Trust boundary": st.column_config.SelectboxColumn(options=BOUNDARY_VALUES, required=True),
            "Sensitive data": st.column_config.CheckboxColumn(),
            "Description": st.column_config.TextColumn(),
        },
    )
    names = [n for n in (_text(v) for v in comps["Name"]) if n]
    flow_df = flows_frame(arch)
    endpoint_options = sorted(set(names) | set(flow_df["Source"]) | set(flow_df["Destination"]))
    st.markdown("**Data flows**")
    flows = st.data_editor(
        flow_df, num_rows="dynamic", hide_index=True, key=f"ed_flows_{draft_id}", width="stretch",
        column_config={
            "Source": st.column_config.SelectboxColumn(options=endpoint_options, required=True),
            "Destination": st.column_config.SelectboxColumn(options=endpoint_options, required=True),
            "Protocol": st.column_config.TextColumn(help="e.g. HTTPS, gRPC, AMQP. Leave as Unspecified if unknown."),
            "Authenticated": st.column_config.SelectboxColumn(options=AUTH_CHOICES),
            "Data": st.column_config.TextColumn(),
        },
    )
    edited, errors = build_architecture(arch, comps, flows)
    for error in errors:
        st.error(error)
    if st.button("Run analysis with these edits", type="primary", disabled=bool(errors), key=f"run_edit_{draft_id}"):
        return edited
    return None
