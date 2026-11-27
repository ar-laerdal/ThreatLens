"""Offline backend: implements the LLM protocol from the local knowledge base, with no network.

Components and data flows are detected by keyword matching; threats, controls, abuse cases and
tests come from knowledge/catalog.json. Output goes through the same schemas, risk engine and
reviewer-flagging as AI output. It cannot read diagram images.
"""
import json
import re
from typing import Sequence

from core.knowledge import GENERIC_TYPES, Mention, find_mentions, load_catalog, type_for_component
from core.llm_client import LLMError
from core.schemas import (
    AbuseCase, AbuseCaseList, Architecture, Asset,
    Component, ControlMapping, ControlMappingList, DataFlow, FrameworkRef, ImagePayload, TestCase,
    TestCaseList, Threat, ThreatList, TrustBoundaryDef,
)

MODEL_NAME = "offline-knowledge-base"
MAX_COMPONENTS = 25
MAX_FLOWS = 40
MAX_THREATS = 35
MAX_FLOW_THREATS = 8
MAX_PER_PATTERN = 2
STOPWORDS = {"the", "a", "an", "our", "all", "each", "every", "this", "that", "its", "and", "or", "to", "of", "in",
             "for", "with", "from", "by", "on", "is", "are", "uses", "use", "via", "then", "also"}
ARROW = re.compile(r"-+>|=+>|→|⇒")
SEGMENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n")
PROTOCOLS = re.compile(r"\b(https|http|mtls|tls|grpc|amqp|ssh|sftp|jdbc|tcp|websocket|smtp)\b", re.I)
AUTH_HINT = re.compile(r"authenticat|jwt|oauth|mtls|bearer|api key|token", re.I)
ENCRYPTED = {"HTTPS", "TLS", "MTLS", "SSH", "SFTP"}
PROFILES = {
    "External": ("Unauthenticated internet user", ["Network access to the public interface"]),
    "DMZ": ("Unauthenticated internet user", ["Network access to the public interface"]),
    "Third-Party": ("Compromised third-party provider", ["The provider or its credentials are compromised"]),
    "Internal": ("Malicious insider or compromised internal workload", ["A foothold inside the internal network"]),
}


def _between(text: str, tag: str) -> str:
    m = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", text, flags=re.DOTALL)
    return m.group(1) if m else ""


def _catalog_index() -> dict[str, dict]:
    """Threat base title -> threat entry (control + test), across types and flow patterns."""
    cat = load_catalog()
    index = {t["title"]: t for info in cat["types"].values() for t in info["threats"]}
    index.update({t["title"]: t for t in cat["flows"].values()})
    return index


def _base_title(title: str, component: str) -> str:
    suffix = f" ({component})"
    return title[: -len(suffix)] if title.endswith(suffix) else title


# --------------------------------------------------------------------------- architecture


def _prefix_words(text: str, start: int) -> str:
    """Up to two capitalised words directly before a keyword on the same line ("Order" in "Order Service")."""
    line_start = text.rfind("\n", 0, start) + 1
    # dots only inside a word (v1.2, S3.bucket), never at its end, so a sentence boundary is not crossed
    adjacent = re.search(r"((?:[A-Za-z][\w\-]*(?:\.[A-Za-z0-9][\w\-]*)*[ \t]+){1,2})$", text[line_start:start])
    if not adjacent:
        return ""
    picked = []
    for w in reversed(adjacent.group(1).split()):
        if w[0].isupper() and w.lower() not in STOPWORDS:
            picked.append(w)
        else:
            break
    return " ".join(reversed(picked))


def _merge_adjacent(text: str, mentions: list[Mention]) -> list[tuple[int, int, str, str]]:
    """Join keyword hits separated only by whitespace ("Payment Service"); the specific type wins."""
    merged: list[tuple[int, int, str, str]] = []
    for m in mentions:
        if merged and re.fullmatch(r"[ \t]+", text[merged[-1][1] : m.start]):
            s, _, key, kw = merged[-1]
            if key in GENERIC_TYPES and m.type_key not in GENERIC_TYPES:
                key = m.type_key
            merged[-1] = (s, m.end, key, kw)
        else:
            merged.append((m.start, m.end, m.type_key, m.keyword))
    return merged


def _label(text: str, start: int, end: int) -> str:
    matched = text[start:end].strip()
    if matched.islower():
        matched = matched.title()
    prefix = _prefix_words(text, start)
    return f"{prefix} {matched}".strip() if prefix else matched


def extract_architecture(text: str) -> Architecture:
    catalog = load_catalog()["types"]
    spans = _merge_adjacent(text, find_mentions(text))

    components: dict[str, Component] = {}
    placed: list[tuple[int, int, str]] = []  # (start, end, component key) for flow detection
    bare: set[str] = set()  # names with no distinguishing prefix, e.g. just "Database"
    for start, end, key, _kw in spans:
        name = _label(text, start, end)
        lower = name.lower()
        if not _prefix_words(text, start):
            bare.add(lower)
        if lower not in components and len(components) < MAX_COMPONENTS:
            line_end = text.find("\n", end)
            line = text[text.rfind("\n", 0, start) + 1 : line_end if line_end != -1 else None]
            info = catalog[key]
            components[lower] = Component(
                name=name, type=info["name"], trust_boundary=info["boundary"],
                handles_sensitive_data=info["sensitive"], evidence=f'Text: "{line.strip()[:100]}"',
                basis="stated", confidence="Medium",
            )
        placed.append((start, end, lower))

    # Fold bare names ("Database") into a more specific component of the same type ("Orders Database").
    for lower in [k for k in components if k in bare]:
        same = [k for k, c in components.items() if c.type == components[lower].type and k not in bare]
        if same:
            placed = [(s, e, same[0] if n == lower else n) for s, e, n in placed]
            del components[lower]
    if not components:
        raise LLMError(
            "Offline mode found no recognisable components (e.g. database, API gateway, auth service). "
            "Use a text/Markdown/PDF design document that names components, or switch to an AI mode."
        )

    flows: dict[tuple[str, str], DataFlow] = {}
    offset = 0
    for seg in SEGMENT_SPLIT.split(text):
        s0 = text.find(seg, offset) if seg else offset
        s1 = s0 + len(seg)
        offset = max(offset, s1)
        inside = [p for p in placed if p[0] >= s0 and p[1] <= s1 and p[2] in components]
        names: list[str] = []
        for _, _, n in inside:
            if not names or names[-1] != n:
                names.append(n)
        if len(names) < 2:
            continue
        pairs = list(zip(names, names[1:])) if ARROW.search(seg) else [(names[0], names[1])]
        proto_m = PROTOCOLS.search(seg)
        protocol = proto_m.group(1).upper() if proto_m else "Unspecified"
        for a, b in pairs:
            if a == b or (a, b) in flows or len(flows) >= MAX_FLOWS:
                continue
            src, dst = components[a], components[b]
            flows[(a, b)] = DataFlow(
                source=src.name, destination=dst.name, protocol=protocol,
                authenticated=True if AUTH_HINT.search(seg) else None,
                crosses_trust_boundary=src.trust_boundary != dst.trust_boundary,
                evidence=f"Text: \"{seg.strip()[:100]}\"", basis="inferred", confidence="Low",
            )

    comps = list(components.values())
    heading = re.search(r"^\s*#\s+(.+)$", text, flags=re.MULTILINE)
    return Architecture(
        system_name=(heading.group(1).strip()[:80] if heading else "Unnamed system"),
        summary=f"Offline keyword-based extraction identified {len(comps)} components and {len(flows)} data flows.",
        components=comps,
        data_flows=list(flows.values()),
        trust_boundaries=[TrustBoundaryDef(name=b) for b in sorted({c.trust_boundary for c in comps})],
        sensitive_assets=[Asset(name=f"Data held by {c.name}", location=c.name) for c in comps if c.handles_sensitive_data],
        assumptions=[
            "Offline mode: components and flows are detected by keyword matching, not by understanding the document.",
            "Trust boundaries come from component-type defaults and are not read from the material.",
        ],
        open_questions=[
            "Were all components and data flows detected? Offline detection can miss or over-match names.",
            "Protocols and authentication marked Unspecified / unknown were not stated in the text.",
        ],
    )


# --------------------------------------------------------------------------- threats


def _clamp(v: int) -> int:
    return max(1, min(5, v))


def _threat(entry: dict, component: str, desc_prefix: str = "", evidence: str = "", l_adj: int = 0, i_adj: int = 0) -> Threat:
    return Threat(
        title=f"{entry['title']} ({component})", affected_component=component, stride_category=entry["stride"],
        description=f"{desc_prefix}{entry['description']}", attack_scenario=entry["scenario"],
        potential_impact=entry["impact_text"], likelihood=_clamp(entry["likelihood"] + l_adj),
        impact=_clamp(entry["impact"] + i_adj),
        evidence=evidence + " Offline catalog pattern; applies if not already mitigated.", confidence="Medium",
    )


def build_threats(arch: Architecture) -> list[Threat]:
    cat = load_catalog()
    threats: list[Threat] = []
    for comp in arch.components:
        key = type_for_component(comp)
        if not key:
            continue
        exposed = 1 if comp.trust_boundary in ("External", "DMZ") else 0
        for entry in cat["types"][key]["threats"]:
            sensitive = 1 if comp.handles_sensitive_data and entry["stride"] in ("Information Disclosure", "Tampering") else 0
            threats.append(_threat(entry, comp.name, evidence=f"Component '{comp.name}' ({comp.type}).",
                                   l_adj=exposed, i_adj=sensitive))

    flow_threats: list[Threat] = []
    for flow in arch.data_flows:
        prefix = f"Flow {flow.source} -> {flow.destination}: "
        evidence = f"Data flow {flow.source} -> {flow.destination} (protocol {flow.protocol})."
        if flow.protocol.upper() not in ENCRYPTED:
            flow_threats.append(_threat(cat["flows"]["unencrypted"], flow.destination, prefix, evidence,
                                        l_adj=1 if flow.crosses_trust_boundary else 0))
        if flow.crosses_trust_boundary and flow.authenticated is not True:
            flow_threats.append(_threat(cat["flows"]["unauthenticated"], flow.destination, prefix, evidence))
    flow_threats.sort(key=lambda t: -(t.likelihood * t.impact))
    threats += flow_threats[:MAX_FLOW_THREATS]

    if not threats:  # unknown component types: fall back to one generic threat per STRIDE category
        first = arch.components[0].name
        for stride, g in cat["generic"].items():
            threats.append(Threat(
                title=f"{stride} risk ({first})", affected_component=first, stride_category=stride,
                description=f"No specific catalog pattern matched; generic {stride} risk applies if not already mitigated.",
                attack_scenario="Generic attacker behaviour for this STRIDE category.", potential_impact=g["control"]["name"],
                likelihood=3, impact=3, evidence="Generic fallback.", confidence="Low",
            ))
    threats.sort(key=lambda t: -(t.likelihood * t.impact))
    # Keep the list varied: at most two instances of the same pattern across components.
    seen: dict[str, int] = {}
    varied = []
    for t in threats:
        base = _base_title(t.title, t.affected_component)
        seen[base] = seen.get(base, 0) + 1
        if seen[base] <= MAX_PER_PATTERN:
            varied.append(t)
    return varied[:MAX_THREATS]


# --------------------------------------------------------------------------- findings-based stages


def _lookup(finding: dict) -> dict:
    """Catalog entry (control + test) for a finding, or the generic STRIDE one."""
    index = _catalog_index()
    base = _base_title(finding["title"], finding["component"])
    if base in index:
        return index[base]
    generic = load_catalog()["generic"].get(finding.get("stride", ""))
    return generic or load_catalog()["generic"]["Tampering"]


def build_controls(findings: list[dict]) -> list[ControlMapping]:
    out = []
    for f in findings:
        c = _lookup(f)["control"]
        out.append(ControlMapping(
            threat_id=f["id"], control=c["name"],
            relevance=f"Addresses '{_base_title(f['title'], f['component'])}' on {f['component']}.",
            implementation=c["implementation"], priority=c["priority"],
            framework_refs=[FrameworkRef(framework=fw, reference=ref) for fw, ref in c["refs"]] +
                           [FrameworkRef(framework="STRIDE", reference=f.get("stride", "Tampering"))],
        ))
    return out


def build_tests(findings: list[dict]) -> list[TestCase]:
    out = []
    for f in findings:
        t = _lookup(f)["test"]
        out.append(TestCase(
            threat_id=f["id"], component=f["component"], objective=t["objective"],
            preconditions=["Testing is authorised by the system owner and performed in a non-production environment."],
            procedure=list(t["steps"]), expected_secure_behavior=t["expected"],
            pass_criteria=f"Every step behaves as expected: {t['expected']}",
            fail_criteria="Any step shows the weakness described in the threat.",
        ))
    return out


def build_abuse_cases(arch: Architecture, findings: list[dict]) -> list[AbuseCase]:
    boundary = {c.name: c.trust_boundary for c in arch.components}
    out = []
    for f in findings[:12]:
        stride = f.get("stride", "")
        profile, pre = PROFILES.get(boundary.get(f["component"], ""), ("External attacker", ["Access to the exposed interface"]))
        if stride == "Repudiation":
            profile, pre = "Dishonest or malicious user", ["A valid account on the system"]
        elif stride == "Elevation of Privilege" and profile.startswith("Unauth"):
            profile, pre = "Authenticated low-privilege user", ["A valid low-privilege account"]
        c = _lookup(f)["control"]
        out.append(AbuseCase(
            title=f"Abuse of {f['component']}: {_base_title(f['title'], f['component'])}",
            attacker_profile=profile, target_component=f["component"], preconditions=pre,
            scenario=f"The attacker targets {f['component']}. {f['description']}",
            security_impact=f"{stride} affecting {f['component']} (severity {f.get('severity', 'unknown')}).",
            prevention_measures=[c["name"], c["implementation"]], related_threat_ids=[f["id"]],
        ))
    return out


# --------------------------------------------------------------------------- client


class OfflineClient:
    model_name = MODEL_NAME

    def generate(
        self,
        *,
        system: str,
        user: str,
        response_model: type,
        images: Sequence[ImagePayload] = (),
        max_tokens: int = 8000,
        stage: str = "llm",
    ):
        if response_model is Architecture:
            text = _between(user, "untrusted_document")
            if not text.strip():
                raise LLMError(
                    "Offline mode cannot read diagram images. Upload a text, Markdown or PDF design document, "
                    "or switch to an AI mode."
                )
            return extract_architecture(text)

        arch_json = _between(user, "architecture_json")
        arch = Architecture.model_validate_json(arch_json) if arch_json else None
        findings: list[dict] = json.loads(_between(user, "findings_json") or "[]")

        if response_model is ThreatList:
            return ThreatList(threats=build_threats(arch))
        if response_model is ControlMappingList:
            return ControlMappingList(controls=build_controls(findings))
        if response_model is TestCaseList:
            return TestCaseList(test_cases=build_tests(findings))
        if response_model is AbuseCaseList:
            return AbuseCaseList(abuse_cases=build_abuse_cases(arch, findings))
        raise LLMError(f"Offline mode does not support stage '{stage}'.")
