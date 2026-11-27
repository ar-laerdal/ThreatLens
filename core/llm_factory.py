"""Analysis modes shown in the UI and the LLM backend each one uses."""
from core.llm_client import LLM, PROVIDER_LABELS, ClaudeClient, current_provider, provider_status
from core.offline_client import OfflineClient
from core.rag import RagLLM

MODE_OFFLINE, MODE_AI, MODE_AI_RAG = "offline", "ai", "ai_rag"
MODE_LABELS = {
    MODE_OFFLINE: "Offline (no API)",
    MODE_AI: "AI (Claude)",
    MODE_AI_RAG: "AI + knowledge base (RAG)",
}
MODE_CAPTIONS = {
    MODE_OFFLINE: "Rules + local knowledge base. No network or API key. Text/Markdown/PDF only (no diagram images).",
    MODE_AI: "Claude analyses the material directly. Needs credentials for the configured provider (LLM_PROVIDER in .env).",
    MODE_AI_RAG: "Claude, grounded with threat patterns and controls retrieved from the local knowledge base.",
}


def ai_status() -> tuple[bool, str, str]:
    """(ready, provider label, hint) for the configured AI provider, without any network call."""
    provider = current_provider()
    ready, hint = provider_status(provider)
    return ready, PROVIDER_LABELS.get(provider, provider), hint


def requires_api(mode: str) -> bool:
    return mode in (MODE_AI, MODE_AI_RAG)


def build_llm(mode: str) -> LLM:
    """Raises LLMConfigError when an AI mode is chosen without usable provider settings."""
    if mode == MODE_OFFLINE:
        return OfflineClient()
    if mode == MODE_AI:
        return ClaudeClient()
    if mode == MODE_AI_RAG:
        return RagLLM(ClaudeClient())
    raise ValueError(f"Unknown analysis mode: {mode}")
