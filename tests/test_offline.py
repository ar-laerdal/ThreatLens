import pytest

from core import knowledge
from core.llm_client import LLMError
from core.llm_factory import MODE_AI, MODE_OFFLINE, build_llm, requires_api
from core.offline_client import OfflineClient
from core.rag import RagLLM
from core.schemas import Architecture, ImagePayload, ProcessedInput, ThreatList
from core.workflow import run_pipeline
from tests.conftest import FakeLLM, make_architecture

DOC = """# Demo Shop
The Web Frontend sends requests over HTTPS to the API Gateway.
The API Gateway validates a JWT with the Authentication Service.
The Order Service reads and writes the Orders Database.
"""


def processed(text=DOC):
    return ProcessedInput(filename="d.md", kind="text", size_bytes=len(text), text=text)


def test_offline_pipeline_end_to_end_without_network():
    model = run_pipeline(OfflineClient(), processed(), "Demo", use_langgraph=False)
    names = model.architecture.component_names()
    assert {"Web Frontend", "API Gateway", "Authentication Service", "Order Service", "Orders Database"} <= set(names)
    assert model.llm_model == "offline-knowledge-base"
    assert model.threats and all(t.id.startswith("T-") and t.severity for t in model.threats)
    valid = {t.id for t in model.threats}
    assert {c.threat_id for c in model.controls} == valid
    assert all(c.status.startswith("Recommended") for c in model.controls)
    assert all(t.threat_id in valid for t in model.test_cases) and model.abuse_cases
    # flows are inferred from text and flagged for human review
    assert any(f.source == "Web Frontend" and f.destination == "API Gateway" for f in model.architecture.data_flows)
    assert all(f.needs_review for f in model.architecture.data_flows)


def test_offline_rejects_images_only_and_unrecognised_text():
    img = ImagePayload(media_type="image/png", data_b64="AAAA")
    with pytest.raises(LLMError, match="diagram images"):
        OfflineClient().generate(system="", user="Analyze", response_model=Architecture, images=[img])
    with pytest.raises(LLMError, match="no recognisable components"):
        OfflineClient().generate(
            system="", user="<untrusted_document>\nHello world\n</untrusted_document>", response_model=Architecture
        )


def test_retriever_finds_relevant_entries():
    top = knowledge.retrieve("sql injection database queries", k=3)
    assert any(e.type_key == "database" for e in top)
    assert knowledge.type_for_text("Orders PostgreSQL") == "database"


def test_rag_wrapper_adds_context_only_where_useful():
    class Spy(FakeLLM):
        def generate(self, **kw):
            self.last = kw
            return super().generate(**kw)

    spy = Spy()
    rag = RagLLM(spy)
    arch = make_architecture()
    rag.generate(system="s", user=f"<architecture_json>\n{arch.model_dump_json()}\n</architecture_json>",
                 response_model=ThreatList, stage="threat_analyzer")
    assert "<knowledge_context>" in spy.last["user"] and "reference DATA" in spy.last["system"]
    rag.generate(system="s", user="doc", response_model=Architecture, stage="architecture_analyzer")
    assert "<knowledge_context>" not in spy.last["user"]
    assert rag.model_name == "fake-model + RAG"


def test_factory_modes(monkeypatch):
    assert isinstance(build_llm(MODE_OFFLINE), OfflineClient) and not requires_api(MODE_OFFLINE)
    assert requires_api(MODE_AI)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from core.llm_client import LLMConfigError
    with pytest.raises(LLMConfigError):
        build_llm(MODE_AI)
