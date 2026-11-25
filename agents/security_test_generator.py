"""Security test case generation. Tests are documentation only; nothing here executes them."""
import json

from core.llm_client import LLM
from core.schemas import Architecture, TestCase, TestCaseList, Threat

BATCH_SIZE = 10

SYSTEM = """Write actionable security test cases that validate mitigations for the threats in <findings_json>.

Each test case: threat_id (one of the supplied IDs), objective, component (exact component name), preconditions \
(list; always include that testing is authorised and performed in a non-production environment), procedure \
(ordered list of concrete steps a tester follows, e.g. "Request /orders/{id} with a token belonging to another \
user"; no exploit code, payload strings, or scanner command lines), expected_secure_behavior, pass_criteria, \
fail_criteria.

Write 1-2 test cases per threat, favouring Critical and High threats. Tests are for authorised validation by \
the system owner only."""


def finalize(tests: list[TestCase], threats: list[Threat]) -> tuple[list[TestCase], list[str]]:
    valid = {t.id for t in threats}
    kept = [t for t in tests if t.threat_id in valid]
    warnings = []
    if len(kept) != len(tests):
        warnings.append(f"{len(tests) - len(kept)} test case(s) referenced unknown threat IDs and were discarded.")
    kept = [t.model_copy(update={"id": f"TC-{i:03d}"}) for i, t in enumerate(kept, start=1)]
    return kept, warnings


def run(llm: LLM, arch: Architecture, threats: list[Threat]) -> tuple[list[TestCase], list[str]]:
    tests: list[TestCase] = []
    for start in range(0, len(threats), BATCH_SIZE):
        batch = threats[start : start + BATCH_SIZE]
        compact = [
            {"id": t.id, "title": t.title, "component": t.affected_component, "stride": t.stride_category,
             "severity": t.severity, "description": t.description, "attack_scenario": t.attack_scenario}
            for t in batch
        ]
        result = llm.generate(
            system=SYSTEM,
            user=(
                f"System: {arch.system_name}\n"
                f"<findings_json>\n{json.dumps(compact, indent=1)}\n</findings_json>"
            ),
            response_model=TestCaseList,
            max_tokens=14000,
            stage="security_test_generator",
        )
        tests.extend(result.test_cases)
    return finalize(tests, threats)
