"""Abuse case generation (defensive framing)."""
import json

from core.llm_client import LLM
from core.schemas import AbuseCase, AbuseCaseList, Architecture, Threat

SYSTEM = """Write realistic abuse cases for defensive security analysis, based on the architecture and the \
identified threats.

Each abuse case: title, attacker_profile (e.g. unauthenticated internet user, malicious customer, compromised \
third party, malicious insider), target_component (exact component name), preconditions (list), scenario \
(narrative at design-review level: what the attacker tries and why it could work; NO exploit code, payloads or \
tool command lines), security_impact, prevention_measures (list), related_threat_ids (IDs from the findings).

Produce 8-15 abuse cases covering the highest-risk threats and a variety of attacker profiles. Each must be \
grounded in the supplied architecture and link to at least one threat ID."""


def finalize(cases: list[AbuseCase], arch: Architecture, threats: list[Threat]) -> list[AbuseCase]:
    valid_ids = {t.id for t in threats}
    names = {n.lower(): n for n in arch.component_names()}
    out = []
    for i, case in enumerate(cases, start=1):
        out.append(
            case.model_copy(
                update={
                    "id": f"AC-{i:03d}",
                    "related_threat_ids": [t for t in case.related_threat_ids if t in valid_ids],
                    "target_component": names.get(case.target_component.lower(), case.target_component),
                }
            )
        )
    return out


def run(llm: LLM, arch: Architecture, threats: list[Threat]) -> list[AbuseCase]:
    compact = [
        {"id": t.id, "title": t.title, "component": t.affected_component, "stride": t.stride_category,
         "severity": t.severity, "description": t.description}
        for t in threats
    ]
    result = llm.generate(
        system=SYSTEM,
        user=(
            f"<architecture_json>\n{arch.model_dump_json(indent=1)}\n</architecture_json>\n\n"
            f"<findings_json>\n{json.dumps(compact, indent=1)}\n</findings_json>"
        ),
        response_model=AbuseCaseList,
        max_tokens=12000,
        stage="abuse_case_generator",
    )
    return finalize(result.abuse_cases, arch, threats)
