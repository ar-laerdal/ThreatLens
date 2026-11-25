"""Guards for knowledge/catalog.json: offline mode finds a threat's control and test by its title, and detects component
types by keyword, so duplicates or invalid values silently break results."""
from collections import Counter

import pytest

from core.knowledge import load_catalog, type_for_text
from core.offline_client import extract_architecture
from core.schemas import FRAMEWORK_VALUES, STRIDE_VALUES

CATALOG = load_catalog()
ENTRIES = [(k, th) for k, ty in CATALOG["types"].items() for th in ty["threats"]] + \
          [("flow", th) for th in CATALOG["flows"].values()]


def test_threat_titles_are_unique():
    dupes = [t for t, n in Counter(th["title"] for _, th in ENTRIES).items() if n > 1]
    assert not dupes


def test_a_keyword_belongs_to_one_type():
    counts = Counter(k.lower() for ty in CATALOG["types"].values() for k in ty["keywords"])
    assert not [k for k, n in counts.items() if n > 1]


@pytest.mark.parametrize("key,threat", ENTRIES, ids=[f"{k}:{th['title'][:40]}" for k, th in ENTRIES])
def test_entry_is_complete_and_valid(key, threat):
    assert threat["stride"] in STRIDE_VALUES
    assert 1 <= threat["likelihood"] <= 5 and 1 <= threat["impact"] <= 5
    for field in ("description", "scenario", "impact_text"):
        assert threat[field].strip()
    control = threat["control"]
    assert control["priority"] in ("Critical", "High", "Medium", "Low") and control["implementation"].strip()
    assert control["refs"] and all(fw in FRAMEWORK_VALUES for fw, _ in control["refs"])
    test = threat["test"]
    assert test["objective"].strip() and test["steps"] and test["expected"].strip()


def test_every_type_has_keywords_threats_and_a_valid_boundary():
    for key, ty in CATALOG["types"].items():
        assert ty["keywords"] and ty["threats"], key
        assert ty["boundary"] in ("External", "DMZ", "Internal", "Third-Party"), key


@pytest.mark.parametrize("phrase,expected", [
    ("Cloudflare", "cdn_waf"), ("Kubernetes cluster", "container_platform"), ("Terraform", "iac_pipeline"),
    ("Notification Service", "notification_service"), ("Search Cluster", "search_engine"),
    ("Data Warehouse", "data_warehouse"), ("Model Serving", "ml_model_service"), ("IoT Device", "iot_edge_device"),
    ("GraphQL API", "graphql_api"), ("FHIR interface", "healthcare_data_interface"),
    ("Backup Service", "backup_service"), ("VPN", "remote_access"),
])
def test_new_component_types_are_detected(phrase, expected):
    assert type_for_text(phrase) == expected


def test_a_sentence_boundary_does_not_leak_into_a_component_name():
    arch = extract_architecture("The API reads the Search Cluster. Kubernetes runs the GraphQL API.")
    assert "Search Cluster" in arch.component_names() and "Kubernetes" in arch.component_names()
