"""Shared fixtures: a fake LLM that returns canned, schema-valid responses (no network)."""
import re

import pytest

from core.schemas import (
    AbuseCase, AbuseCaseList, Architecture, Component, ControlMapping, ControlMappingList, DataFlow,
    FrameworkRef, ProcessedInput, TestCase, TestCaseList, Threat, ThreatList,
)


def make_architecture() -> Architecture:
    return Architecture(
        system_name="Demo Shop",
        summary="Tiny shop.",
        components=[
            Component(name="API Gateway", type="API Gateway", trust_boundary="DMZ"),
            Component(name="User Database", type="Database", trust_boundary="Internal", handles_sensitive_data=True),
        ],
        data_flows=[DataFlow(source="API Gateway", destination="User Database", data="queries", protocol="TLS")],
    )


def make_threat(title="SQL injection", component="User Database", stride="Tampering", l=4, i=5) -> Threat:
    return Threat(
        title=title, affected_component=component, stride_category=stride, description="d",
        attack_scenario="a", potential_impact="p", likelihood=l, impact=i,
    )


class FakeLLM:
    model_name = "fake-model"

    def __init__(self, threats=None, fail_on=None):
        self.threats = threats or [
            make_threat("SQL injection", "User Database", "Tampering", 4, 5),
            make_threat("Token theft", "API Gateway", "Spoofing", 3, 4),
            make_threat("Ghost threat", "Not A Component", "Spoofing", 1, 1),
        ]
        self.fail_on = fail_on
        self.calls = []

    def generate(self, *, system, user, response_model, images=(), max_tokens=8000, stage="llm"):
        self.calls.append(stage)
        if stage == self.fail_on:
            raise RuntimeError("boom")
        if response_model is Architecture:
            return make_architecture()
        if response_model is ThreatList:
            return ThreatList(threats=self.threats)
        ids = re.findall(r"T-\d{3}", user) + ["T-999"]
        if response_model is AbuseCaseList:
            return AbuseCaseList(abuse_cases=[AbuseCase(
                title="Abuse", attacker_profile="Anon", target_component="api gateway", scenario="s",
                security_impact="i", related_threat_ids=[ids[0], "T-999"])])
        if response_model is ControlMappingList:
            return ControlMappingList(controls=[
                ControlMapping(threat_id=t, control="Parameterised queries", relevance="r", implementation="impl",
                               framework_refs=[FrameworkRef(framework="OWASP Top 10", reference="A03")], priority="High")
                for t in dict.fromkeys(ids)])  # includes unknown T-999
        if response_model is TestCaseList:
            return TestCaseList(test_cases=[TestCase(
                threat_id=t, objective="o", component="c", procedure=["step"], expected_secure_behavior="e",
                pass_criteria="p", fail_criteria="f") for t in dict.fromkeys(ids)])
        raise AssertionError(f"unexpected model {response_model}")


@pytest.fixture
def fake_llm():
    return FakeLLM()


@pytest.fixture
def processed():
    return ProcessedInput(filename="design.md", kind="text", size_bytes=10, text="A shop with a gateway and DB.")
