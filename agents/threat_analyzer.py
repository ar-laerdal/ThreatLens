"""STRIDE threat identification."""
from core import risk_engine
from core.llm_client import LLM
from core.schemas import Architecture, Threat, ThreatList

MAX_THREATS = 40

SYSTEM = """Perform a STRIDE threat model of the architecture in <architecture_json>.

Cover all six categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, \
Elevation of Privilege) where applicable; prioritise trust-boundary crossings, authentication, data stores and \
third-party integrations. Produce at most 35 distinct, specific threats (not generic checklists).

For each threat give: title, affected_component (exact component name from the architecture), stride_category, \
description, attack_scenario (defensive-analysis level, no exploit code), potential_impact, \
likelihood (integer 1-5: 1 rare ... 5 almost certain), impact (integer 1-5: 1 negligible ... 5 severe), \
evidence (which architecture element/flow supports it; if it rests on an assumption say \
"Assumption: ..."), and confidence (High | Medium | Low).

Rate likelihood and impact honestly and spread them; do not rate everything high. Do not assume a control is \
missing or present unless the architecture says so; if unknown, say the threat applies "if not already mitigated"."""


def _match_component(name: str, arch: Architecture) -> str | None:
    lowered = name.strip().lower()
    for comp in arch.component_names():
        if comp.lower() == lowered:
            return comp
    return None


def finalize(threats: list[Threat], arch: Architecture) -> list[Threat]:
    """Ground against the architecture, score, rank, and assign stable IDs."""
    out = []
    for threat in threats:
        exact = _match_component(threat.affected_component, arch)
        if exact:
            threat = threat.model_copy(update={"affected_component": exact, "grounded": True})
        else:
            threat = threat.model_copy(update={"grounded": False, "confidence": "Low"})
        # Review state is human-owned; never accept it from the model.
        threat = threat.model_copy(update={"review_status": "Unreviewed"})
        out.append(risk_engine.apply_risk(threat))
    out = risk_engine.sort_threats(out)[:MAX_THREATS]
    return [t.model_copy(update={"id": f"T-{i:03d}"}) for i, t in enumerate(out, start=1)]


def run(llm: LLM, arch: Architecture) -> list[Threat]:
    result = llm.generate(
        system=SYSTEM,
        user=f"<architecture_json>\n{arch.model_dump_json(indent=1)}\n</architecture_json>",
        response_model=ThreatList,
        max_tokens=16000,
        stage="threat_analyzer",
    )
    return finalize(result.threats, arch)
