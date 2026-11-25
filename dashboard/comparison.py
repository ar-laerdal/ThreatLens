"""Manual vs AI comparison with transparent, caveated metrics."""
import pandas as pd
import streamlit as st

from core import comparison
from core.schemas import ThreatModel

PLACEHOLDER = """One threat per line. Optional format: title | component
Stolen session tokens allow account takeover | Web Frontend
Order IDs can be enumerated to read other users' orders | Application Backend
No rate limiting on login | API Gateway"""


def render(model: ThreatModel) -> None:
    st.title("Manual vs AI Comparison")
    st.info("Enter the threats your team identified manually for this same architecture. Matching is a simple "
            "word-overlap heuristic, so every pair is shown for you to verify. More findings does not mean more "
            "accurate: AI-only findings may be false positives until reviewed.")

    text = st.text_area("Manually identified threats", height=200, placeholder=PLACEHOLDER, key="manual_threats")
    minutes = st.number_input("Time taken for the manual review (minutes)", min_value=0.0, value=0.0, step=5.0)
    manual = comparison.parse_manual_threats(text)
    if not manual:
        st.caption("Enter at least one manual threat to see the comparison.")
        return

    result = comparison.compare(manual, model.threats)

    cols = st.columns(5)
    cols[0].metric("Manual threats", result.manual_total)
    cols[1].metric("AI threats", result.ai_total)
    cols[2].metric("Common (matched)", len(result.matches))
    cols[3].metric("AI-only", len(result.ai_only))
    cols[4].metric("Manual-only", len(result.manual_only))

    ai_seconds = model.ai_duration_seconds
    st.dataframe(
        pd.DataFrame([
            {"Metric": "Review time", "Manual": f"{minutes:.0f} min" if minutes else "not entered",
             "AI": f"{ai_seconds:.0f} s (generation only, excludes human review of output)"},
            {"Metric": "Threats listed", "Manual": result.manual_total, "AI": result.ai_total},
            {"Metric": "Share also found by the other method",
             "Manual": f"{comparison.overlap_percent(result, 'manual')}% of manual threats found by AI",
             "AI": f"{comparison.overlap_percent(result, 'ai')}% of AI threats found manually"},
        ]), hide_index=True,
    )

    st.subheader("Common threats (verify each pair)")
    if result.matches:
        st.dataframe(pd.DataFrame([
            {"Manual": m.manual.title, "AI": f"{m.ai.id} {m.ai.title}", "Similarity": m.score} for m in result.matches
        ]), hide_index=True)
    else:
        st.write("No matches above the similarity threshold.")

    left, right = st.columns(2)
    with left:
        st.subheader("AI-only findings")
        st.caption("Tick the ones you judge valid after review.")
        valid = 0
        for t in result.ai_only:
            if st.checkbox(f"{t.id} [{t.severity}] {t.title}", key=f"cmp_valid_{t.id}"):
                valid += 1
        if result.ai_only:
            st.metric("AI-only findings you validated", f"{valid} / {len(result.ai_only)}")
    with right:
        st.subheader("Manual-only findings")
        st.caption("Threats the AI did not report (or matched too loosely to detect).")
        for m in result.manual_only:
            st.markdown(f"- {m.title}")

    st.caption("The AI and manual lists can differ because of wording, scope or genuine gaps. Use these numbers to "
               "start a discussion, not to rank the methods.")
