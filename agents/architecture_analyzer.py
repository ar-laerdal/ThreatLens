"""Architecture Analyzer: diagram/document -> structured, grounded Architecture JSON."""
from core.llm_client import LLM, wrap_untrusted
from core.schemas import Architecture, ProcessedInput

SYSTEM = """You are extracting a system architecture for a security review.

Extract ONLY what the material supports:
- components (frontends, backend services, APIs/endpoints, databases/storage, external integrations, \
authentication services, queues, etc.) with type, description and trust_boundary \
(External | DMZ | Internal | Third-Party | Unknown)
- data_flows between components, with the data carried, protocol, whether authentication is stated, and whether \
it crosses a trust boundary
- trust_boundaries / network boundaries, and sensitive_assets (data and assets worth protecting)

For every component and data flow set:
- basis: "stated" if shown/written explicitly, "inferred" if you are interpreting (e.g. an unlabeled arrow, an \
unnamed box, a protocol not shown). Use "Unspecified" for unknown protocols, never guess "HTTPS".
- evidence: a short quote or pointer (e.g. "box labelled 'API Gateway'", "section 3.2")
- confidence: High | Medium | Low; set needs_review=true with a review_reason for anything uncertain.

Do not invent components or connections. List unclear points in open_questions and your interpretations in \
assumptions. Data flow source/destination must exactly match a component name."""


def reconcile(arch: Architecture) -> Architecture:
    """Flag items a human must review; never silently drop or fix them."""
    names = {c.name.strip().lower() for c in arch.components}
    for comp in arch.components:
        if comp.basis == "inferred" or comp.confidence == "Low":
            comp.needs_review = True
            comp.review_reason = comp.review_reason or "Inferred or low-confidence interpretation."
    for flow in arch.data_flows:
        missing = [n for n in (flow.source, flow.destination) if n.strip().lower() not in names]
        if missing:
            flow.needs_review = True
            flow.review_reason = f"Endpoint not among identified components: {', '.join(missing)}."
        elif flow.basis == "inferred" or flow.confidence == "Low":
            flow.needs_review = True
            flow.review_reason = flow.review_reason or "Inferred or low-confidence interpretation."
    return arch


def run(llm: LLM, processed: ProcessedInput) -> Architecture:
    parts = ["Analyze the following architecture material and produce the architecture JSON."]
    if processed.images:
        parts.append(f"{len(processed.images)} image(s) are attached: architecture diagram(s) to analyze.")
    if processed.text:
        parts.append(wrap_untrusted(processed.text))
    arch = llm.generate(
        system=SYSTEM,
        user="\n\n".join(parts),
        response_model=Architecture,
        images=processed.images,
        max_tokens=8000,
        stage="architecture_analyzer",
    )
    return reconcile(arch)
