"""Deterministic risk scoring (5x5 likelihood x impact matrix).

The LLM proposes likelihood and impact ratings (1-5); score and severity are computed here so
the methodology is identical for every threat and every run.

    score = likelihood * impact
    Critical >= 20, High 12-19, Medium 6-11, Low <= 5
"""
from collections import Counter
from typing import Iterable

from core.schemas import STRIDE_VALUES, Architecture, Threat

LIKELIHOOD_LABELS = {1: "Rare", 2: "Unlikely", 3: "Possible", 4: "Likely", 5: "Almost certain"}
IMPACT_LABELS = {1: "Negligible", 2: "Minor", 3: "Moderate", 4: "Major", 5: "Severe"}
SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_COLORS = {"Critical": "#FF4D6D", "High": "#FF9F1C", "Medium": "#FFD166", "Low": "#4CC9F0"}

METHODOLOGY = (
    "Risk score = likelihood (1-5) x impact (1-5). "
    "Critical: 20-25, High: 12-19, Medium: 6-11, Low: 1-5. "
    "Ratings are AI-proposed and must be confirmed by a human reviewer."
)


def risk_score(likelihood: int, impact: int) -> int:
    return likelihood * impact


def severity_for(score: int) -> str:
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def apply_risk(threat: Threat) -> Threat:
    score = risk_score(threat.likelihood, threat.impact)
    return threat.model_copy(update={"risk_score": score, "severity": severity_for(score)})


def sort_threats(threats: Iterable[Threat]) -> list[Threat]:
    return sorted(threats, key=lambda t: (-t.risk_score, t.affected_component, t.title))


def severity_counts(threats: Iterable[Threat]) -> dict[str, int]:
    counts = Counter(t.severity for t in threats)
    return {s: counts.get(s, 0) for s in SEVERITIES}


def stride_counts(threats: Iterable[Threat]) -> dict[str, int]:
    counts = Counter(t.stride_category for t in threats)
    return {s: counts.get(s, 0) for s in STRIDE_VALUES}


def component_risk(threats: Iterable[Threat]) -> dict[str, dict[str, int]]:
    """component -> {severity: count}"""
    out: dict[str, dict[str, int]] = {}
    for t in threats:
        bucket = out.setdefault(t.affected_component, {s: 0 for s in SEVERITIES})
        bucket[t.severity] += 1
    return out


def summarize(architecture: Architecture, threats: list[Threat]) -> dict:
    return {
        "components": len(architecture.components),
        "threats": len(threats),
        **severity_counts(threats),
    }
