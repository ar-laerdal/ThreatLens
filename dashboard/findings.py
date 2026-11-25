"""Abuse cases, security controls and security test views."""
import streamlit as st

from core.schemas import ThreatModel
from dashboard.common import SEV_ICON


def render_abuse_cases(model: ThreatModel) -> None:
    st.title("Abuse Cases")
    st.caption("Defensive scenarios describing how the design could be misused. Not exploit instructions.")
    covered = {tid for a in model.abuse_cases for tid in a.related_threat_ids}
    m1, m2, m3 = st.columns(3)
    m1.metric("Abuse cases", len(model.abuse_cases))
    m2.metric("Attacker profiles", len({a.attacker_profile for a in model.abuse_cases}))
    m3.metric("Threats covered", f"{len(covered)} of {len(model.threats)}")
    profiles = sorted({a.attacker_profile for a in model.abuse_cases})
    chosen = st.multiselect("Attacker profile", profiles)
    for a in model.abuse_cases:
        if chosen and a.attacker_profile not in chosen:
            continue
        with st.expander(f"{a.id} - {a.title}  |  target: {a.target_component}"):
            st.markdown(f"**Attacker profile:** {a.attacker_profile}")
            st.markdown("**Preconditions**\n" + "\n".join(f"- {p}" for p in a.preconditions))
            st.markdown(f"**Abuse scenario**\n\n{a.scenario}")
            st.markdown(f"**Expected security impact**\n\n{a.security_impact}")
            st.markdown("**Recommended prevention**\n" + "\n".join(f"- {p}" for p in a.prevention_measures))
            st.caption("Related threats: " + (", ".join(a.related_threat_ids) or "none"))


def render_controls(model: ThreatModel) -> None:
    st.title("Security Controls")
    st.warning("These are **recommended** controls. The tool does not know whether any of them already exist.")
    mapped = {c.threat_id for c in model.controls}
    prio = {p: sum(c.priority == p for c in model.controls) for p in ["Critical", "High", "Medium", "Low"]}
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Controls", len(model.controls)); m2.metric("Threats covered", f"{len(mapped)} of {len(model.threats)}")
    m3.metric(f"{SEV_ICON['Critical']} Critical", prio["Critical"]); m4.metric(f"{SEV_ICON['High']} High", prio["High"])
    m5.metric(f"{SEV_ICON['Medium']} Medium / Low", prio["Medium"] + prio["Low"])
    priorities = st.multiselect("Priority", ["Critical", "High", "Medium", "Low"])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for c in sorted(model.controls, key=lambda c: (order[c.priority], c.threat_id)):
        if priorities and c.priority not in priorities:
            continue
        threat = model.threat_by_id(c.threat_id)
        with st.expander(f"[{c.priority}] {c.control}  ->  {c.threat_id}" + (f" {threat.title}" if threat else "")):
            st.markdown(f"**Why relevant:** {c.relevance}")
            st.markdown(f"**Implementation recommendation:** {c.implementation}")
            st.markdown("**Framework references**\n" + "\n".join(f"- {r.framework}: {r.reference}" for r in c.framework_refs))
            st.caption(f"Status: {c.status}")
    st.caption("Framework identifiers are AI-suggested; verify them against the current OWASP / MITRE / NIST publications.")


def render_tests(model: ThreatModel) -> None:
    st.title("Security Testing")
    st.error("Test cases are documentation only; this application never executes them. Run only with written "
             "authorisation, in non-production environments you own.")
    tested = {t.threat_id for t in model.test_cases}
    m1, m2, m3 = st.columns(3)
    m1.metric("Test cases", len(model.test_cases))
    m2.metric("Threats with a test", f"{len(tested)} of {len(model.threats)}")
    m3.metric("Components tested", len({t.component for t in model.test_cases}))
    component = st.multiselect("Component", sorted({t.component for t in model.test_cases}))
    for tc in model.test_cases:
        if component and tc.component not in component:
            continue
        with st.expander(f"{tc.id} - {tc.component}  (threat {tc.threat_id})"):
            st.markdown(f"**Objective:** {tc.objective}")
            st.markdown("**Preconditions**\n" + "\n".join(f"- {p}" for p in tc.preconditions))
            st.markdown("**Procedure**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(tc.procedure, 1)))
            st.markdown(f"**Expected secure behavior:** {tc.expected_secure_behavior}")
            st.success(f"Pass: {tc.pass_criteria}")
            st.error(f"Fail: {tc.fail_criteria}")
