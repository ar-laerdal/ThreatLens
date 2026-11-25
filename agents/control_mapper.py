"""Map threats to security controls and framework references."""
import json

from core.llm_client import LLM
from core.schemas import Architecture, ControlMapping, ControlMappingList, Threat

BATCH_SIZE = 10

SYSTEM = """Map each threat in <findings_json> to at least one recommended security control.

For each control: threat_id (must be one of the supplied IDs), control (short name), relevance (why it addresses \
this threat), implementation (concrete, actionable guidance for this architecture), framework_refs (1-4 items, \
each {framework, reference}) and priority (Critical | High | Medium | Low).

Allowed frameworks: "OWASP Top 10" (e.g. "A01:2021 Broken Access Control"), "OWASP ASVS" (e.g. "V2.1 Password \
Security" - use requirement-area IDs you are confident exist), "MITRE ATT&CK" (technique IDs you are confident \
exist, e.g. "T1078 Valid Accounts"; use the closest relevant technique), "NIST CSF" (e.g. "PR.AC Access \
Control"), "STRIDE" (the category mitigated). Prefer fewer, accurate references over many guessed ones.

These are RECOMMENDATIONS. Never state or imply that a control is already implemented."""


def finalize(controls: list[ControlMapping], threats: list[Threat]) -> tuple[list[ControlMapping], list[str]]:
    valid = {t.id for t in threats}
    kept = [c for c in controls if c.threat_id in valid]
    warnings = []
    dropped = len(controls) - len(kept)
    if dropped:
        warnings.append(f"{dropped} control mapping(s) referenced unknown threat IDs and were discarded.")
    unmapped = sorted(valid - {c.threat_id for c in kept})
    if unmapped:
        warnings.append(f"No control mapping was produced for: {', '.join(unmapped)}.")
    return kept, warnings


def run(llm: LLM, arch: Architecture, threats: list[Threat]) -> tuple[list[ControlMapping], list[str]]:
    controls: list[ControlMapping] = []
    for start in range(0, len(threats), BATCH_SIZE):
        batch = threats[start : start + BATCH_SIZE]
        compact = [
            {"id": t.id, "title": t.title, "component": t.affected_component, "stride": t.stride_category,
             "severity": t.severity, "description": t.description}
            for t in batch
        ]
        result = llm.generate(
            system=SYSTEM,
            user=(
                f"System: {arch.system_name}\n"
                f"<findings_json>\n{json.dumps(compact, indent=1)}\n</findings_json>"
            ),
            response_model=ControlMappingList,
            max_tokens=12000,
            stage="control_mapper",
        )
        controls.extend(result.controls)
    return finalize(controls, threats)
