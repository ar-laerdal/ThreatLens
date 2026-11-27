"""Transparent manual-vs-AI threat comparison.

Matching is a simple, inspectable heuristic (token overlap + optional component/STRIDE agreement),
not a semantic judgement. The UI shows every matched pair so a human can verify it.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

from core.schemas import STRIDE_VALUES, Threat

MATCH_THRESHOLD = 0.5
STOPWORDS = {
    "a", "an", "the", "of", "to", "in", "on", "and", "or", "for", "via", "by", "with", "from", "is", "are",
    "can", "may", "could", "attack", "attacker", "threat", "risk", "through", "using", "into", "at", "as",
}


@dataclass
class ManualThreat:
    title: str
    component: str = ""
    stride: str = ""


@dataclass
class Match:
    manual: ManualThreat
    ai: Threat
    score: float


@dataclass
class ComparisonResult:
    matches: list[Match] = field(default_factory=list)
    manual_only: list[ManualThreat] = field(default_factory=list)
    ai_only: list[Threat] = field(default_factory=list)
    manual_total: int = 0
    ai_total: int = 0


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def tokens(text: str) -> set[str]:
    return {_stem(w) for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOPWORDS and len(w) > 1}


def _stride_from(text: str) -> str:
    key = re.sub(r"[^a-z]", "", text.lower())
    for value in STRIDE_VALUES:
        if re.sub(r"[^a-z]", "", value.lower()) == key:
            return value
    return {"dos": "Denial of Service", "eop": "Elevation of Privilege"}.get(key, "")


def parse_manual_threats(text: str) -> list[ManualThreat]:
    """One threat per line: 'title' or 'title | component | STRIDE category'. Bullets/numbering are ignored."""
    out = []
    for line in text.splitlines():
        line = re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", line).strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        out.append(
            ManualThreat(
                title=parts[0],
                component=parts[1] if len(parts) > 1 else "",
                stride=_stride_from(parts[2]) if len(parts) > 2 else "",
            )
        )
    return out


def similarity(manual: ManualThreat, ai: Threat) -> float:
    m_tokens = tokens(f"{manual.title} {manual.component}")
    if not m_tokens:
        return 0.0
    ai_tokens = tokens(f"{ai.title} {ai.affected_component} {ai.description} {ai.stride_category}")
    score = len(m_tokens & ai_tokens) / len(m_tokens)  # share of the manual threat's words found in the AI threat
    if manual.component and manual.component.lower() == ai.affected_component.lower():
        score += 0.15
    if manual.stride and manual.stride == ai.stride_category:
        score += 0.15
    return min(score, 1.0)


def compare(manual: list[ManualThreat], ai: list[Threat], threshold: float = MATCH_THRESHOLD) -> ComparisonResult:
    """Greedy one-to-one matching by descending similarity."""
    candidates = sorted(
        ((similarity(m, a), mi, ai_i) for mi, m in enumerate(manual) for ai_i, a in enumerate(ai)),
        key=lambda c: -c[0],
    )
    used_m, used_a, matches = set(), set(), []
    for score, mi, ai_i in candidates:
        if score < threshold:
            break
        if mi in used_m or ai_i in used_a:
            continue
        used_m.add(mi)
        used_a.add(ai_i)
        matches.append(Match(manual[mi], ai[ai_i], round(score, 2)))
    return ComparisonResult(
        matches=matches,
        manual_only=[m for i, m in enumerate(manual) if i not in used_m],
        ai_only=[a for i, a in enumerate(ai) if i not in used_a],
        manual_total=len(manual),
        ai_total=len(ai),
    )


def overlap_percent(result: ComparisonResult, of: str = "manual") -> Optional[float]:
    total = result.manual_total if of == "manual" else result.ai_total
    return round(100 * len(result.matches) / total, 1) if total else None
