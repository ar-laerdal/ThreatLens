import pytest

from core import risk_engine
from tests.conftest import make_threat


@pytest.mark.parametrize(
    "likelihood,impact,expected",
    [(5, 5, "Critical"), (5, 4, "Critical"), (4, 4, "High"), (3, 4, "High"), (3, 3, "Medium"),
     (2, 3, "Medium"), (1, 5, "Low"), (1, 1, "Low")],
)
def test_severity_matrix(likelihood, impact, expected):
    assert risk_engine.severity_for(risk_engine.risk_score(likelihood, impact)) == expected


def test_apply_risk_overrides_llm_values():
    t = make_threat(l=5, i=5).model_copy(update={"severity": "Low", "risk_score": 0})
    scored = risk_engine.apply_risk(t)
    assert (scored.risk_score, scored.severity) == (25, "Critical")


def test_counts_and_sorting():
    threats = [risk_engine.apply_risk(make_threat(l=l, i=i, component=c))
               for l, i, c in [(1, 1, "A"), (5, 5, "B"), (3, 3, "B")]]
    ordered = risk_engine.sort_threats(threats)
    assert [t.risk_score for t in ordered] == [25, 9, 1]
    assert risk_engine.severity_counts(threats) == {"Critical": 1, "High": 0, "Medium": 1, "Low": 1}
    assert sum(risk_engine.stride_counts(threats).values()) == 3
    assert risk_engine.component_risk(threats)["B"]["Critical"] == 1
