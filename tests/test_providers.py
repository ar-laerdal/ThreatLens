import anthropic
import pytest

from core import llm_client
from core.llm_client import ClaudeClient, LLMConfigError, current_provider, provider_status, resolve_model
from core.llm_factory import ai_status

ENV_VARS = [
    "LLM_PROVIDER", "LLM_MODEL", "ANTHROPIC_MODEL", "ANTHROPIC_API_KEY", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_BEARER_TOKEN_BEDROCK", "ANTHROPIC_FOUNDRY_RESOURCE",
    "ANTHROPIC_FOUNDRY_BASE_URL", "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_AUTH",
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


class Recorder:
    """Stands in for an SDK client class and records how it was constructed."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs


class Raises:
    """A client whose messages.stream(...) raises the given exception."""

    def __init__(self, exc):
        outer = exc

        class Messages:
            def stream(self, **_):
                raise outer

        self.messages = Messages()


@pytest.fixture
def fake_sdk(monkeypatch):
    for name in ("Anthropic", "AnthropicBedrockMantle", "AnthropicFoundry"):
        monkeypatch.setattr(anthropic, name, type(name, (Recorder,), {}))


def test_default_provider_is_the_anthropic_api(fake_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    client = ClaudeClient()
    assert client.provider == "anthropic" and type(client._client).__name__ == "Anthropic"
    assert client._client.kwargs == {"api_key": "k"}
    assert client.model_name == "claude-sonnet-5-5"  # no provider suffix for the Anthropic API


def test_anthropic_model_env_still_works(fake_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-5-5")
    assert ClaudeClient().model_name == "claude-opus-5-5"


def test_bedrock_uses_region_prefixed_model_and_aws_credential_chain(fake_sdk, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    client = ClaudeClient()
    assert type(client._client).__name__ == "AnthropicBedrockMantle"
    assert client._client.kwargs == {"aws_region": "eu-west-1"}
    assert client._model_id == "anthropic.claude-sonnet-5-5" and client.model_name.endswith("(bedrock)")


def test_bedrock_needs_a_region(fake_sdk, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    with pytest.raises(LLMConfigError, match="AWS_REGION"):
        ClaudeClient()


def test_foundry_with_api_key_and_custom_deployment(fake_sdk, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "Foundry")  # case-insensitive
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "my-resource")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "secret")
    monkeypatch.setenv("LLM_MODEL", "sonnet-deployment")
    client = ClaudeClient()
    assert type(client._client).__name__ == "AnthropicFoundry"
    assert client._client.kwargs == {"resource": "my-resource", "api_key": "secret"}
    assert client._model_id == "sonnet-deployment" and client.model_name == "sonnet-deployment (foundry)"


def test_foundry_base_url_replaces_resource(fake_sdk, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "foundry")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_BASE_URL", "https://example.test/anthropic")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "secret")
    assert ClaudeClient()._client.kwargs == {"base_url": "https://example.test/anthropic", "api_key": "secret"}


def test_foundry_requires_resource_and_credentials(fake_sdk, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "foundry")
    with pytest.raises(LLMConfigError, match="ANTHROPIC_FOUNDRY_RESOURCE"):
        ClaudeClient()
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "r")
    with pytest.raises(LLMConfigError, match="API_KEY"):
        ClaudeClient()


def test_foundry_entra_without_azure_identity_explains_how_to_fix(fake_sdk, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "foundry")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "r")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_AUTH", "entra")
    monkeypatch.setitem(__import__("sys").modules, "azure", None)  # make the import fail
    with pytest.raises(LLMConfigError, match="azure-identity"):
        ClaudeClient()


def test_unknown_provider_is_rejected(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    with pytest.raises(LLMConfigError, match="Unknown LLM_PROVIDER"):
        ClaudeClient()
    assert provider_status()[0] is False


def test_provider_status_checks_settings_without_network(monkeypatch):
    assert provider_status("anthropic") == (False, "Set ANTHROPIC_API_KEY in .env.")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert provider_status("anthropic")[0]
    assert "AWS_REGION" in provider_status("bedrock")[1]
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    assert provider_status("bedrock")[0]
    assert "FOUNDRY_RESOURCE" in provider_status("foundry")[1]
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "r")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_AUTH", "entra")
    assert provider_status("foundry")[0]


def test_ai_status_reports_the_configured_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    ready, label, hint = ai_status()
    assert not ready and label == "Amazon Bedrock" and "AWS_REGION" in hint


def test_resolve_model_precedence(monkeypatch):
    assert resolve_model("bedrock") == "anthropic.claude-sonnet-5-5"
    monkeypatch.setenv("ANTHROPIC_MODEL", "legacy")
    assert resolve_model("anthropic") == "legacy" and resolve_model("bedrock") == "anthropic.claude-sonnet-5-5"
    monkeypatch.setenv("LLM_MODEL", "explicit")
    assert resolve_model("anthropic") == resolve_model("bedrock") == "explicit"
    assert current_provider() == "anthropic"


@pytest.mark.parametrize("error_name,hint", [
    ("AuthenticationError", "rejected the credentials"),
    ("PermissionDeniedError", "denied access"),
    ("NotFoundError", "was not found"),
])
def test_provider_errors_become_actionable_config_errors(fake_sdk, monkeypatch, error_name, hint):
    monkeypatch.setenv("LLM_PROVIDER", "foundry")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_RESOURCE", "r")
    monkeypatch.setenv("ANTHROPIC_FOUNDRY_API_KEY", "k")
    client = ClaudeClient()
    raised = getattr(anthropic, error_name).__new__(getattr(anthropic, error_name))

    client._client = Raises(raised)
    with pytest.raises(LLMConfigError, match=hint):
        client._call("sys", [{"role": "user", "content": "x"}], 10)


def test_missing_aws_credentials_become_a_config_error(fake_sdk, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    client = ClaudeClient()

    class NoCredentialsError(Exception):
        pass

    client._client = Raises(NoCredentialsError("Unable to locate credentials"))
    with pytest.raises(LLMConfigError, match="AWS credentials"):
        client._call("sys", [{"role": "user", "content": "x"}], 10)
