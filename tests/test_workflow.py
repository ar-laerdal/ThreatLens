import pytest

from core.workflow import StageError, run_pipeline
from tests.conftest import FakeLLM


@pytest.mark.parametrize("use_langgraph", [False, True])
def test_full_pipeline(fake_llm, processed, use_langgraph):
    if use_langgraph:
        pytest.importorskip("langgraph")
    events = []
    model = run_pipeline(fake_llm, processed, "Demo", on_progress=lambda s, m: events.append(s),
                         use_langgraph=use_langgraph)

    assert events == ["architecture", "threats", "abuse_cases", "controls", "tests"]
    assert model.project_name == "Demo" and model.llm_model == "fake-model"

    # IDs are assigned by code, ordered by risk score, highest first.
    assert [t.id for t in model.threats] == ["T-001", "T-002", "T-003"]
    assert model.threats[0].severity == "Critical" and model.threats[0].risk_score == 20
    # A threat on an unknown component is kept but flagged, never silently trusted.
    ghost = next(t for t in model.threats if t.title == "Ghost threat")
    assert not ghost.grounded and ghost.confidence == "Low"

    # References to unknown threat IDs are discarded and reported.
    valid = {t.id for t in model.threats}
    assert all(c.threat_id in valid for c in model.controls)
    assert all(t.threat_id in valid for t in model.test_cases)
    assert all(set(a.related_threat_ids) <= valid for a in model.abuse_cases)
    assert model.abuse_cases[0].target_component == "API Gateway"
    assert any("unknown threat IDs" in w for w in model.warnings)
    assert all(c.status.startswith("Recommended") for c in model.controls)
    assert [t.id for t in model.test_cases] == ["TC-001", "TC-002", "TC-003"]


def test_stage_failure_is_reported_with_stage_name(processed):
    with pytest.raises(StageError) as err:
        run_pipeline(FakeLLM(fail_on="threat_analyzer"), processed, "Demo", use_langgraph=False)
    assert err.value.stage == "threats"


def test_workflow_stops_after_failed_stage(processed):
    llm = FakeLLM(fail_on="threat_analyzer")
    with pytest.raises(StageError):
        run_pipeline(llm, processed, "Demo", use_langgraph=False)
    assert "abuse_case_generator" not in llm.calls
