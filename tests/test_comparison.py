from core import comparison
from tests.conftest import make_threat


def test_parse_manual_threats_formats():
    items = comparison.parse_manual_threats("- SQL injection | User Database | tampering\n2) Weak passwords\n\n")
    assert [m.title for m in items] == ["SQL injection", "Weak passwords"]
    assert items[0].component == "User Database" and items[0].stride == "Tampering"


def test_match_and_partition():
    ai = [make_threat("SQL injection in database queries", "User Database", "Tampering"),
          make_threat("Replay of stolen tokens", "API Gateway", "Spoofing")]
    manual = comparison.parse_manual_threats("SQL injection | User Database | Tampering\nSubdomain takeover")
    result = comparison.compare(manual, ai)
    assert len(result.matches) == 1 and result.matches[0].ai.title.startswith("SQL")
    assert [m.title for m in result.manual_only] == ["Subdomain takeover"]
    assert [a.title for a in result.ai_only] == ["Replay of stolen tokens"]
    assert comparison.overlap_percent(result, "manual") == 50.0


def test_matching_is_one_to_one():
    ai = [make_threat("SQL injection")]
    manual = comparison.parse_manual_threats("SQL injection\nSQL injection attack")
    result = comparison.compare(manual, ai)
    assert len(result.matches) == 1 and len(result.manual_only) == 1


def test_empty_inputs():
    result = comparison.compare([], [])
    assert comparison.overlap_percent(result) is None
