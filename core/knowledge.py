"""Local threat knowledge base: catalog loading, keyword typing and a small BM25 retriever.

Shared by offline mode (which generates everything from the catalog) and by AI + RAG mode (which
injects the retrieved entries into the prompts). No network and no third-party dependencies.
"""
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from core.schemas import Architecture, Component

CATALOG_PATH = Path(__file__).resolve().parent.parent / "knowledge" / "catalog.json"
GENERIC_TYPES = {"backend_service"}  # matched by very common words; lowest priority


@lru_cache(maxsize=1)
def load_catalog() -> dict:
    with CATALOG_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- keyword typing


@lru_cache(maxsize=1)
def _patterns() -> list[tuple[str, str, "re.Pattern[str]"]]:
    out = []
    for key, entry in load_catalog()["types"].items():
        for kw in entry["keywords"]:
            out.append((key, kw, re.compile(rf"(?<![A-Za-z0-9]){re.escape(kw)}(?:s|es)?(?![A-Za-z0-9])", re.I)))
    return out


@dataclass(frozen=True)
class Mention:
    start: int
    end: int
    type_key: str
    keyword: str


def find_mentions(text: str) -> list[Mention]:
    """Non-overlapping component-type keyword hits in text order (longest keyword wins)."""
    hits = [Mention(m.start(), m.end(), key, kw) for key, kw, pat in _patterns() for m in pat.finditer(text)]
    hits.sort(key=lambda h: (-(h.end - h.start), h.start))
    taken: list[Mention] = []
    for hit in hits:
        if all(hit.end <= t.start or hit.start >= t.end for t in taken):
            taken.append(hit)
    return sorted(taken, key=lambda h: h.start)


def type_for_text(text: str) -> Optional[str]:
    """Best catalog type for a short label, preferring specific types over the generic one."""
    mentions = find_mentions(text)
    if not mentions:
        return None
    specific = [m for m in mentions if m.type_key not in GENERIC_TYPES] or mentions
    return max(specific, key=lambda m: m.end - m.start).type_key


def type_for_component(comp: Component) -> Optional[str]:
    types = load_catalog()["types"]
    for key, entry in types.items():
        if comp.type.strip().lower() == entry["name"].lower():
            return key
    for text in (f"{comp.type} {comp.name}", " ".join([comp.description, *comp.technologies])):
        key = type_for_text(text)
        if key:
            return key
    return None


# --------------------------------------------------------------------------- BM25 retrieval


@dataclass(frozen=True)
class Entry:
    type_key: str
    type_name: str
    threat: dict

    def render(self) -> str:
        t, c = self.threat, self.threat["control"]
        refs = "; ".join(f"{fw} {ref}" for fw, ref in c["refs"])
        return (
            f"- [{self.type_name}] {t['title']} ({t['stride']}): {t['description']} "
            f"Typical control: {c['name']} - {c['implementation']} (refs: {refs})"
        )


def _tokens(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 2]


@lru_cache(maxsize=1)
def _index() -> tuple[list[Entry], list[Counter], dict[str, float], float]:
    catalog = load_catalog()
    entries: list[Entry] = []
    for key, tinfo in catalog["types"].items():
        entries += [Entry(key, tinfo["name"], t) for t in tinfo["threats"]]
    entries += [Entry("flow", "Data Flow", t) for t in catalog["flows"].values()]
    docs = []
    for e in entries:
        t = e.threat
        docs.append(Counter(_tokens(f"{e.type_name} {t['title']} {t['stride']} {t['description']} {t['control']['name']}")))
    n = len(docs)
    df: Counter = Counter(tok for d in docs for tok in d)
    idf = {tok: math.log(1 + (n - c + 0.5) / (c + 0.5)) for tok, c in df.items()}
    avg = sum(sum(d.values()) for d in docs) / n
    return entries, docs, idf, avg


def retrieve(query: str, k: int = 8, k1: float = 1.5, b: float = 0.75) -> list[Entry]:
    entries, docs, idf, avg = _index()
    q = set(_tokens(query))
    scored = []
    for entry, doc in zip(entries, docs):
        length = sum(doc.values())
        score = sum(
            idf[tok] * doc[tok] * (k1 + 1) / (doc[tok] + k1 * (1 - b + b * length / avg)) for tok in q if tok in doc
        )
        if score > 0:
            scored.append((score, entry))
    scored.sort(key=lambda s: -s[0])
    return [e for _, e in scored[:k]]


def context_for_architecture(arch: Architecture, per_component: int = 3) -> list[Entry]:
    """Catalog entries matching each component's type, plus data-flow patterns."""
    catalog = load_catalog()
    out: list[Entry] = []
    seen: set[str] = set()
    for comp in arch.components:
        key = type_for_component(comp)
        if key and key not in seen:
            seen.add(key)
            info = catalog["types"][key]
            out += [Entry(key, info["name"], t) for t in info["threats"][:per_component]]
    out += [Entry("flow", "Data Flow", t) for t in catalog["flows"].values()]
    return out


def format_context(entries: list[Entry]) -> str:
    if not entries:
        return ""
    return "<knowledge_context>\n" + "\n".join(e.render() for e in entries) + "\n</knowledge_context>"
