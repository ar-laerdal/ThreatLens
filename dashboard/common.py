"""Small helpers shared by several dashboard pages."""
import streamlit as st

from core.schemas import ThreatModel

SEV_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}
STATUSES = ["Unreviewed", "Confirmed", "Rejected"]


def review_counts(model: ThreatModel) -> dict[str, int]:
    return {s: sum(t.review_status == s for t in model.threats) for s in STATUSES}


def render_review_progress(model: ThreatModel) -> None:
    counts = review_counts(model)
    total = len(model.threats) or 1
    done = counts["Confirmed"] + counts["Rejected"]
    st.progress(done / total, text=f"Human review: {done} of {len(model.threats)} threats reviewed "
                                   f"({counts['Confirmed']} confirmed, {counts['Rejected']} rejected, "
                                   f"{counts['Unreviewed']} still to review)")


def by_threat(model: ThreatModel) -> dict[str, dict[str, list]]:
    """threat id -> its controls, abuse cases and tests."""
    out = {t.id: {"controls": [], "cases": [], "tests": []} for t in model.threats}
    for c in model.controls:
        out.get(c.threat_id, {}).get("controls", []).append(c)
    for a in model.abuse_cases:
        for tid in a.related_threat_ids:
            out.get(tid, {}).get("cases", []).append(a)
    for x in model.test_cases:
        out.get(x.threat_id, {}).get("tests", []).append(x)
    return out


def short(text: str, limit: int = 150) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
