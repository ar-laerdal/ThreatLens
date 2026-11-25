"""Step tracker for the analysis run: per-stage status, elapsed time and an overall progress bar."""
import time
from typing import Optional, Sequence

import streamlit as st

ICONS = {"pending": "⬜", "running": "⏳", "done": "✅", "skipped": "☑️", "failed": "❌"}


def _format(label: str, state: str, detail: str) -> str:
    return f"{ICONS[state]} **{label}**" + (f"  ·  {detail}" if detail else "")


class StepTracker:
    def __init__(self, stages: Sequence[tuple[str, str]], skipped: dict[str, str] | None = None):
        self.stages = list(stages)
        self.state = {key: "pending" for key, _ in self.stages}
        self.detail = {key: "" for key, _ in self.stages}
        for key, note in (skipped or {}).items():
            if key in self.state:
                self.state[key], self.detail[key] = "skipped", note
        self.started: dict[str, float] = {}
        self.current: Optional[str] = None
        self.bar = st.progress(0.0, text="Starting...")
        self.box = st.empty()
        self.render()

    def _finish_current(self) -> None:
        if self.current and self.state[self.current] == "running":
            self.state[self.current] = "done"
            self.detail[self.current] = f"{time.perf_counter() - self.started[self.current]:.1f}s"

    def start(self, key: str) -> None:
        self._finish_current()
        self.current = key
        self.state[key] = "running"
        self.started[key] = time.perf_counter()
        self.render()

    def finish(self) -> None:
        self._finish_current()
        self.current = None
        self.render()

    def fail(self) -> None:
        if self.current:
            self.state[self.current] = "failed"
        self.render()

    def summary(self) -> list[str]:
        return [_format(label, self.state[key], self.detail[key]) for key, label in self.stages]

    def render(self) -> None:
        done = sum(s in ("done", "skipped") for s in self.state.values())
        running = next((label for key, label in self.stages if self.state[key] == "running"), None)
        text = f"{running}..." if running else (f"{done} of {len(self.stages)} steps complete")
        self.bar.progress(done / len(self.stages), text=text)
        self.box.markdown("\n\n".join(self.summary()))
