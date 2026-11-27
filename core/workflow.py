"""Agent workflow: analyze -> STRIDE -> abuse cases -> controls -> tests -> assemble.

Uses LangGraph when installed (each node is a plain function, so the graph is only wiring) and
falls back to running the same nodes sequentially otherwise.
"""
import logging
import time
from typing import Callable, Optional, TypedDict

from agents import (
    abuse_case_generator,
    architecture_analyzer,
    control_mapper,
    security_test_generator,
    threat_analyzer,
)
from core.llm_client import LLM, LLMError
from core.schemas import (
    AbuseCase,
    Architecture,
    ControlMapping,
    ProcessedInput,
    TestCase,
    Threat,
    ThreatModel,
)

log = logging.getLogger("threat_agent.workflow")

ProgressFn = Callable[[str, str], None]  # (stage_key, human message)

STAGES = [
    ("architecture", "Analyzing architecture"),
    ("threats", "Identifying STRIDE threats"),
    ("abuse_cases", "Generating abuse cases"),
    ("controls", "Mapping security controls"),
    ("tests", "Generating security test cases"),
]


class StageError(Exception):
    def __init__(self, stage: str, cause: Exception):
        super().__init__(f"Stage '{stage}' failed: {cause}")
        self.stage = stage
        self.cause = cause


class PipelineState(TypedDict, total=False):
    processed: ProcessedInput
    architecture: Architecture
    threats: list[Threat]
    abuse_cases: list[AbuseCase]
    controls: list[ControlMapping]
    test_cases: list[TestCase]
    warnings: list[str]


def _make_nodes(llm: LLM, on_progress: Optional[ProgressFn]):
    def notify(stage: str, msg: str) -> None:
        if on_progress:
            on_progress(stage, msg)

    def guarded(stage: str, label: str, fn):
        def node(state: PipelineState) -> PipelineState:
            notify(stage, label)
            try:
                return fn(state)
            except StageError:
                raise
            except Exception as exc:
                # Message only: exceptions here never include document content.
                log.error("stage=%s failed: %s", stage, type(exc).__name__)
                raise StageError(stage, exc) from exc

        return node

    def architecture(state):
        arch = architecture_analyzer.run(llm, state["processed"])
        warnings = list(state.get("warnings", []))
        flagged = sum(c.needs_review for c in arch.components) + sum(f.needs_review for f in arch.data_flows)
        if flagged:
            warnings.append(f"{flagged} architecture item(s) are inferred or uncertain and need human review.")
        return {"architecture": arch, "warnings": warnings}

    def threats(state):
        found = threat_analyzer.run(llm, state["architecture"])
        warnings = list(state.get("warnings", []))
        ungrounded = [t.id for t in found if not t.grounded]
        if ungrounded:
            warnings.append(f"Threats referencing components not in the architecture: {', '.join(ungrounded)}.")
        return {"threats": found, "warnings": warnings}

    def abuse(state):
        return {"abuse_cases": abuse_case_generator.run(llm, state["architecture"], state["threats"])}

    def controls(state):
        found, warns = control_mapper.run(llm, state["architecture"], state["threats"])
        return {"controls": found, "warnings": list(state.get("warnings", [])) + warns}

    def tests(state):
        found, warns = security_test_generator.run(llm, state["architecture"], state["threats"])
        return {"test_cases": found, "warnings": list(state.get("warnings", [])) + warns}

    labels = dict(STAGES)
    return [
        ("analyze_architecture", guarded("architecture", labels["architecture"], architecture)),
        ("identify_threats", guarded("threats", labels["threats"], threats)),
        ("generate_abuse_cases", guarded("abuse_cases", labels["abuse_cases"], abuse)),
        ("map_controls", guarded("controls", labels["controls"], controls)),
        ("generate_tests", guarded("tests", labels["tests"], tests)),
    ]


def _execute(nodes, state: PipelineState, use_langgraph: bool) -> PipelineState:
    if use_langgraph:
        try:
            from langgraph.graph import END, START, StateGraph
        except ImportError:
            log.info("langgraph not installed; using sequential runner")
        else:
            graph = StateGraph(PipelineState)
            for name, fn in nodes:
                graph.add_node(name, fn)
            graph.add_edge(START, nodes[0][0])
            for (a, _), (b, _) in zip(nodes, nodes[1:]):
                graph.add_edge(a, b)
            graph.add_edge(nodes[-1][0], END)
            return graph.compile().invoke(state)

    for _, fn in nodes:
        state = {**state, **fn(state)}
    return state


def analyze_architecture(llm: LLM, processed: ProcessedInput) -> Architecture:
    """Run only the architecture stage, so a person can review and edit it before threats are generated."""
    try:
        return architecture_analyzer.run(llm, processed)
    except Exception as exc:
        if isinstance(exc, LLMError):
            raise
        log.error("stage=architecture failed: %s", type(exc).__name__)
        raise StageError("architecture", exc) from exc


def run_pipeline(
    llm: LLM,
    processed: ProcessedInput,
    project_name: str,
    on_progress: Optional[ProgressFn] = None,
    use_langgraph: bool = True,
    architecture: Optional[Architecture] = None,
) -> ThreatModel:
    """Run the full workflow. Raises StageError identifying the failed stage.

    When `architecture` is given (e.g. reviewed and edited by a person) the architecture stage is skipped.
    """
    started = time.perf_counter()
    initial: PipelineState = {"processed": processed, "warnings": list(processed.warnings)}
    nodes = _make_nodes(llm, on_progress)
    if architecture is not None:
        initial["architecture"] = architecture
        nodes = [n for n in nodes if n[0] != "analyze_architecture"]
    final = _execute(nodes, initial, use_langgraph)
    elapsed = time.perf_counter() - started

    return ThreatModel(
        project_name=project_name or final["architecture"].system_name,
        source_filename=processed.filename,
        source_kind=processed.kind,
        source_size_bytes=processed.size_bytes,
        architecture=final["architecture"],
        threats=final["threats"],
        abuse_cases=final["abuse_cases"],
        controls=final["controls"],
        test_cases=final["test_cases"],
        warnings=final.get("warnings", []),
        llm_model=getattr(llm, "model_name", ""),
        ai_duration_seconds=round(elapsed, 1),
    )


__all__ = ["run_pipeline", "analyze_architecture", "StageError", "STAGES", "LLMError"]
