import pytest

pytest.importorskip("reportlab")

from core.schemas import ThreatModel
from core import risk_engine
from reports.pdf_generator import build_pdf
from tests.conftest import make_architecture, make_threat


def test_pdf_builds_and_escapes_markup():
    t = risk_engine.apply_risk(make_threat(title="<b>Bad & <i>markup</b>")).model_copy(update={"id": "T-001"})
    model = ThreatModel(project_name="P & Q <x>", architecture=make_architecture(), threats=[t])
    pdf = build_pdf(model)
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000
