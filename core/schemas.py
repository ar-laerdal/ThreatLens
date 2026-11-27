"""Pydantic models shared by every agent, the dashboard and the report generator.

LLM output is validated against these models. Normalisers are deliberately lenient about
casing/aliases (e.g. "dos" -> "Denial of Service") but strict about structure, so malformed
responses are rejected and retried instead of silently accepted.
"""
import re
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------- normalisers


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _canon(options: list[str], aliases: Optional[dict[str, str]] = None):
    table = {_key(o): o for o in options}
    table.update({_key(k): v for k, v in (aliases or {}).items()})

    def validator(value):
        if isinstance(value, str):
            return table.get(_key(value), value.strip())
        return value

    return BeforeValidator(validator)


STRIDE_VALUES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]
STRIDE_ALIASES = {
    "dos": "Denial of Service",
    "eop": "Elevation of Privilege",
    "privilege escalation": "Elevation of Privilege",
    "info disclosure": "Information Disclosure",
}
CONFIDENCE_VALUES = ["High", "Medium", "Low"]
BOUNDARY_VALUES = ["External", "DMZ", "Internal", "Third-Party", "Unknown"]
PRIORITY_VALUES = ["Critical", "High", "Medium", "Low"]
FRAMEWORK_VALUES = ["OWASP Top 10", "OWASP ASVS", "MITRE ATT&CK", "NIST CSF", "STRIDE"]
FRAMEWORK_ALIASES = {
    "owasp top ten": "OWASP Top 10",
    "owasptop10": "OWASP Top 10",
    "top 10": "OWASP Top 10",
    "asvs": "OWASP ASVS",
    "owasp application security verification standard": "OWASP ASVS",
    "mitre": "MITRE ATT&CK",
    "mitre attack": "MITRE ATT&CK",
    "attack": "MITRE ATT&CK",
    "nist": "NIST CSF",
    "nist cybersecurity framework": "NIST CSF",
    "nist cybersecurity framework csf": "NIST CSF",
}

Stride = Annotated[Literal[tuple(STRIDE_VALUES)], _canon(STRIDE_VALUES, STRIDE_ALIASES)]

Confidence = Annotated[Literal[tuple(CONFIDENCE_VALUES)], _canon(CONFIDENCE_VALUES)]
TrustBoundary = Annotated[
    Literal[tuple(BOUNDARY_VALUES)],
    _canon(BOUNDARY_VALUES, {"third party": "Third-Party", "external": "External", "public": "External"}),
]
Priority = Annotated[Literal[tuple(PRIORITY_VALUES)], _canon(PRIORITY_VALUES)]
Framework = Annotated[Literal[tuple(FRAMEWORK_VALUES)], _canon(FRAMEWORK_VALUES, FRAMEWORK_ALIASES)]
Basis = Annotated[Literal["stated", "inferred"], _canon(["stated", "inferred"], {"explicit": "stated", "assumed": "inferred"})]
ReviewStatus = Literal["Unreviewed", "Confirmed", "Rejected"]


def _to_rating(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(round(value))
    if isinstance(value, str) and re.fullmatch(r"\s*\d+(\.\d+)?\s*", value):
        return int(round(float(value)))
    return value


Rating = Annotated[int, BeforeValidator(_to_rating), Field(ge=1, le=5)]


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)


# --------------------------------------------------------------------------- architecture


class Component(_Base):
    name: str = Field(min_length=1)
    type: str = "Unknown"
    description: str = ""
    trust_boundary: TrustBoundary = "Unknown"
    technologies: list[str] = []
    handles_sensitive_data: bool = False
    evidence: str = ""
    basis: Basis = "stated"
    confidence: Confidence = "High"
    needs_review: bool = False
    review_reason: str = ""


class DataFlow(_Base):
    source: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    data: str = ""
    protocol: str = "Unspecified"
    authenticated: Optional[bool] = None
    crosses_trust_boundary: bool = False
    evidence: str = ""
    basis: Basis = "stated"
    confidence: Confidence = "High"
    needs_review: bool = False
    review_reason: str = ""


class TrustBoundaryDef(_Base):
    name: str
    description: str = ""


class Asset(_Base):
    name: str
    sensitivity: str = "Unknown"
    location: str = ""


class Architecture(_Base):
    system_name: str = "Unnamed system"
    summary: str = ""
    components: list[Component] = Field(min_length=1)
    data_flows: list[DataFlow] = []
    trust_boundaries: list[TrustBoundaryDef] = []
    sensitive_assets: list[Asset] = []
    assumptions: list[str] = []
    open_questions: list[str] = []

    def component_names(self) -> list[str]:
        return [c.name for c in self.components]


# --------------------------------------------------------------------------- findings


class Threat(_Base):
    id: str = ""
    title: str = Field(min_length=1)
    affected_component: str = Field(min_length=1)
    stride_category: Stride
    description: str
    attack_scenario: str
    potential_impact: str
    likelihood: Rating
    impact: Rating
    evidence: str = ""
    confidence: Confidence = "Medium"
    # Computed by core.risk_engine, never trusted from the LLM.
    risk_score: int = 0
    severity: Literal["Critical", "High", "Medium", "Low"] = "Low"
    # False when the component is not in the extracted architecture.
    grounded: bool = True
    review_status: ReviewStatus = "Unreviewed"


class ThreatList(_Base):
    threats: list[Threat] = Field(min_length=1)


class AbuseCase(_Base):
    id: str = ""
    title: str
    attacker_profile: str
    target_component: str
    preconditions: list[str] = []
    scenario: str
    security_impact: str
    prevention_measures: list[str] = []
    related_threat_ids: list[str] = []


class AbuseCaseList(_Base):
    abuse_cases: list[AbuseCase] = Field(min_length=1)


class FrameworkRef(_Base):
    framework: Framework
    reference: str


IMPLEMENTATION_STATUS = "Recommended - not verified as implemented"


class ControlMapping(_Base):
    threat_id: str
    control: str
    relevance: str
    implementation: str
    framework_refs: list[FrameworkRef] = Field(min_length=1)
    priority: Priority = "Medium"
    # Always forced: a recommendation is never evidence that a control exists.
    status: str = IMPLEMENTATION_STATUS

    @field_validator("status", mode="before")
    @classmethod
    def _force_status(cls, _value):
        return IMPLEMENTATION_STATUS


class ControlMappingList(_Base):
    controls: list[ControlMapping] = Field(min_length=1)


class TestCase(_Base):
    __test__ = False  # keep pytest from collecting this as a test class

    id: str = ""
    threat_id: str
    objective: str
    component: str
    preconditions: list[str] = []
    procedure: list[str] = Field(min_length=1)
    expected_secure_behavior: str
    pass_criteria: str
    fail_criteria: str


class TestCaseList(_Base):
    __test__ = False

    test_cases: list[TestCase] = Field(min_length=1)


# --------------------------------------------------------------------------- pipeline I/O


class ImagePayload(BaseModel):
    media_type: str
    data_b64: str
    description: str = ""


class ProcessedInput(BaseModel):
    """Sanitised representation of an upload. Contains untrusted content."""

    filename: str
    kind: Literal["image", "pdf", "text"]
    size_bytes: int
    text: str = ""
    images: list[ImagePayload] = []
    warnings: list[str] = []
    page_count: int = 0


class ThreatModel(BaseModel):
    project_name: str
    source_filename: str = ""
    source_kind: str = ""
    source_size_bytes: int = 0
    architecture: Architecture
    threats: list[Threat] = []
    abuse_cases: list[AbuseCase] = []
    controls: list[ControlMapping] = []
    test_cases: list[TestCase] = []
    warnings: list[str] = []
    llm_model: str = ""
    analysis_mode: str = ""
    ai_duration_seconds: float = 0.0
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def threat_by_id(self, threat_id: str) -> Optional[Threat]:
        return next((t for t in self.threats if t.id == threat_id), None)
