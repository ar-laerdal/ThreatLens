"""ThreatLens - AI-powered threat modeling. Streamlit entry point.

Run:  streamlit run app.py
"""
import hashlib
import importlib.util
import logging
import os
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")

from core.llm_client import LLMConfigError, LLMError  # noqa: E402
from core.llm_factory import MODE_AI, MODE_CAPTIONS, MODE_LABELS, MODE_OFFLINE, ai_status, build_llm, requires_api  # noqa: E402
from core.offline_client import extract_architecture  # noqa: E402
from core.workflow import STAGES, StageError, analyze_architecture, run_pipeline  # noqa: E402
from dashboard import architecture, arch_editor, comparison, findings, overview, threats  # noqa: E402
from dashboard.common import SEV_ICON, render_review_progress  # noqa: E402
from dashboard.progress import StepTracker  # noqa: E402
from processors.url_fetcher import UrlFetchError, fetch_url  # noqa: E402
from processors.document_processor import ALLOWED_EXTENSIONS, MAX_FILE_BYTES, FileValidationError, process_upload  # noqa: E402
from reports.pdf_generator import build_pdf  # noqa: E402

SAMPLE_DIR = Path(__file__).parent / "data" / "sample_architecture"
NAV_GROUPS = [
    ("Home", [("Dashboard", "🏠")]),
    ("Setup", [("Upload Architecture", "📤")]),
    ("Results", [("Architecture Analysis", "🧩"), ("Threat Analysis", "⚠️")]),
    ("Outputs", [("Abuse Cases", "🥷"), ("Security Controls", "🛡️"), ("Security Testing", "🧪"), ("Reports", "📄")]),
    ("Evaluate", [("Manual vs AI", "⚖️")]),
]
ALWAYS_AVAILABLE = {"Dashboard", "Upload Architecture"}  # everything else needs an analysis

ASSETS_DIR = Path(__file__).parent / "assets"

st.set_page_config(page_title="ThreatLens", page_icon=str(ASSETS_DIR / "logo_icon.svg"), layout="wide")
st.logo(str(ASSETS_DIR / "logo.svg"), icon_image=str(ASSETS_DIR / "logo_icon.svg"))

st.markdown(
    """
<style>
.block-container {padding-top: 2rem;}
[data-testid="stMetric"], .sev-card, .finding {
    background:#111B2E; border:1px solid #1F2D45; border-radius:10px; padding:12px 16px;}
.sev-label {color:#8B98A9; font-size:0.85rem;}
.sev-value {font-size:2rem; font-weight:700;}
.finding {margin-bottom:8px;}
h1, h2, h3 {letter-spacing:-0.01em;}
</style>
""",
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- helpers
def sample_files() -> dict[str, Path]:
    files = {"Design document (Markdown)": SAMPLE_DIR / "ecommerce_design.md"}
    diagram = SAMPLE_DIR / "ecommerce_architecture.png"
    if not diagram.exists():
        try:  # generated on demand with Pillow
            spec = importlib.util.spec_from_file_location("generate_diagram", SAMPLE_DIR / "generate_diagram.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.generate(diagram)
        except Exception:
            logging.getLogger("threat_agent.app").warning("could not generate sample diagram")
    if diagram.exists():
        files["Architecture diagram (PNG)"] = diagram
    return files


def current_file():
    """A newly uploaded file wins over a loaded sample; clicking a sample overrides the current upload."""
    upload = st.session_state.get("uploader")
    sample = st.session_state.get("sample_file")
    if upload is not None and upload.file_id != st.session_state.get("ignored_upload_id"):
        return upload.name, upload.getvalue()
    return sample


def last_run_banner() -> None:
    """Shown under the Dashboard title: what just ran, and where to look next."""
    done = st.session_state.get("just_analyzed")
    if not done:
        return
    st.success(f"Analysis complete: {done['threats']} threats found ({MODE_LABELS.get(done['mode'], done['mode'])}, "
               f"{done['seconds']:.0f}s). Explore the details from the sidebar: **Threat Analysis**, **Abuse Cases**, "
               "**Security Controls**, **Security Testing**, and **Reports** to export.")
    with st.expander("How this analysis ran (steps and timings)"):
        st.markdown("\n\n".join(done["steps"]))


def default_project(name: str) -> str:
    return "Pasted architecture" if name == "pasted_architecture.md" else Path(name).stem


def go_to(page: str) -> None:
    st.session_state["nav"] = page


def clear_selection() -> None:
    upload = st.session_state.get("uploader")
    st.session_state["ignored_upload_id"] = upload.file_id if upload else None
    st.session_state.pop("sample_file", None)
    st.session_state["project_name"] = ""


def select_sample(path: Path) -> None:
    st.session_state["sample_file"] = (path.name, path.read_bytes())
    st.session_state["project_name"] = "ShopFast E-Commerce (sample)"
    upload = st.session_state.get("uploader")
    st.session_state["ignored_upload_id"] = upload.file_id if upload else None


def select_pasted() -> None:
    text = st.session_state.get("pasted_text", "").strip()
    if not text:
        return
    st.session_state["sample_file"] = ("pasted_architecture.md", text.encode("utf-8"))
    st.session_state["project_name"] = ""
    upload = st.session_state.get("uploader")
    st.session_state["ignored_upload_id"] = upload.file_id if upload else None


def select_fetched(name: str, data: bytes) -> None:
    st.session_state["sample_file"] = (name, data)
    st.session_state["project_name"] = Path(name).stem
    upload = st.session_state.get("uploader")
    st.session_state["ignored_upload_id"] = upload.file_id if upload else None


def _prepare(name: str, data: bytes, mode: str):
    """Validate the upload and build the LLM backend. Returns (processed, llm) or None after showing an error."""
    try:
        processed = process_upload(name, data)
    except FileValidationError as exc:
        st.error(f"Upload rejected: {exc}")
        return None
    for warning in processed.warnings:
        st.warning(warning)
    try:
        return processed, build_llm(mode)
    except LLMConfigError as exc:
        st.error(str(exc))
        return None


def run_analysis(name: str, data: bytes, project: str, mode: str, architecture=None, processed=None) -> None:
    llm = None
    if processed is None:
        prepared = _prepare(name, data, mode)
        if prepared is None:
            return
        processed, llm = prepared
    else:
        try:
            llm = build_llm(mode)
        except LLMConfigError as exc:
            st.error(str(exc))
            return

    with st.status("Running threat modeling workflow...", expanded=True) as status:
        tracker = StepTracker(STAGES, skipped={"architecture": "reviewed by you"} if architecture else None)
        try:
            model = run_pipeline(llm, processed, project, on_progress=lambda stage, msg: tracker.start(stage),
                                 architecture=architecture)
        except StageError as exc:
            tracker.fail()
            status.update(label=f"Failed at stage: {exc.stage}", state="error")
            st.error(f"The '{exc.stage}' stage failed ({type(exc.cause).__name__}): {exc.cause}")
            return
        except LLMError as exc:
            tracker.fail()
            status.update(label="LLM error", state="error")
            st.error(str(exc))
            return
        tracker.finish()
        status.update(label=f"Done in {model.ai_duration_seconds:.0f}s", state="complete")

    model.analysis_mode = mode
    st.session_state["model"] = model
    st.session_state.pop("pdf_bytes", None)
    st.session_state.pop("draft", None)
    # Go straight to the results. The rerun also unlocks the result pages in the sidebar.
    st.session_state["just_analyzed"] = {"threats": len(model.threats), "mode": mode, "steps": tracker.summary(),
                                         "seconds": model.ai_duration_seconds}
    st.session_state["toast_done"] = True
    st.session_state["nav"] = "Dashboard"
    st.rerun()


def start_review(name: str, data: bytes, mode: str, key: str) -> None:
    """Run only the architecture stage and keep the result for editing."""
    prepared = _prepare(name, data, mode)
    if prepared is None:
        return
    processed, llm = prepared
    with st.spinner("Detecting components and data flows..."):
        try:
            arch = analyze_architecture(llm, processed)
        except StageError as exc:
            st.error(f"The architecture stage failed ({type(exc.cause).__name__}): {exc.cause}")
            return
        except LLMError as exc:
            st.error(str(exc))
            return
    st.session_state["draft"] = {"key": key, "arch": arch, "processed": processed, "id": key[:8]}


# --------------------------------------------------------------------------- pages
def page_upload() -> None:
    st.title("Upload Architecture")
    st.caption("Uploads are treated as untrusted data: validated, never executed, and never written to disk.")
    api_ok, provider_label, provider_hint = ai_status()

    # ---- step 1: mode
    st.subheader("1 · Choose analysis mode")
    if "analysis_mode" not in st.session_state:
        st.session_state["analysis_mode"] = MODE_AI if api_ok else MODE_OFFLINE
    mode = st.radio(
        "Analysis mode", list(MODE_LABELS), key="analysis_mode", horizontal=True, label_visibility="collapsed",
        format_func=lambda m: MODE_LABELS[m] + ("  (needs credentials)" if requires_api(m) and not api_ok else ""),
        captions=[MODE_CAPTIONS[m] for m in MODE_LABELS],
    )
    no_key = requires_api(mode) and not api_ok

    # ---- step 2: input
    st.subheader("2 · Provide your architecture")
    exts = sorted(e.lstrip(".") for e in ALLOWED_EXTENSIONS)
    tab_upload, tab_paste, tab_url, tab_sample = st.tabs(["📄 Upload a file", "📋 Paste details", "🔗 Confluence / URL", "🧪 Try the sample"])
    with tab_upload:
        st.file_uploader(
            "Architecture diagram or design document", type=exts, key="uploader",
            help=f"Accepted: {', '.join(exts)} · max {MAX_FILE_BYTES // (1024 * 1024)} MB",
        )
        st.caption(f"Accepted: {', '.join(exts)} · max {MAX_FILE_BYTES // (1024 * 1024)} MB. "
                   "Diagrams (PNG/JPG) need an AI mode.")
    with tab_paste:
        st.text_area(
            "Architecture details", key="pasted_text", height=260,
            placeholder="Describe your system: components (web app, API gateway, auth service, database, queues, "
                        "third-party services), how they connect (e.g. 'API Gateway -> Orders Database over TLS'), "
                        "trust boundaries and sensitive data.",
        )
        pasted = st.session_state.get("pasted_text", "")
        too_big = len(pasted.encode("utf-8")) > MAX_FILE_BYTES
        st.caption(f"{len(pasted):,} characters. Pasted text is treated as untrusted data, like an uploaded file. "
                   "Naming components and connections explicitly gives the best results, especially in Offline mode.")
        if too_big:
            st.warning(f"Text exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit.")
        st.button("Use this text", key="use_pasted", type="primary", on_click=select_pasted,
                  disabled=not pasted.strip() or too_big)
    with tab_url:
        st.text_input("Confluence page or web link", key="page_url", placeholder="https://your-company.atlassian.net/wiki/spaces/ARCH/pages/123456/Design")
        st.caption("Only the page text is fetched (https only, no internal addresses). Fetched content is treated "
                   "as untrusted data, like an upload. Private Confluence pages need CONFLUENCE_* settings in .env.")
        if st.button("Fetch page", key="fetch_url", type="primary", disabled=not st.session_state.get("page_url", "").strip()):
            with st.spinner("Fetching page..."):
                try:
                    select_fetched(*fetch_url(st.session_state["page_url"]))
                except UrlFetchError as exc:
                    st.error(str(exc))
    with tab_sample:
        st.caption("A ready-made e-commerce platform (ShopFast) so you can try the tool without your own files. "
                   "The design document works in every mode; the diagram needs an AI mode.")
        samples = sample_files()
        for col, (label, path) in zip(st.columns(len(samples)), samples.items()):
            col.button(f"Load: {label}", key=f"sample_{path.name}", width="stretch",
                       on_click=select_sample, args=(path,))

    file = current_file()
    if not file:
        return
    name, data = file
    suffix = Path(name).suffix.lower()
    is_image = suffix in (".png", ".jpg", ".jpeg")
    is_text = suffix in (".txt", ".md", ".markdown")

    # ---- step 3: review and analyze
    st.subheader("3 · Review and analyze")
    size = f"{len(data)} B" if len(data) < 1024 else f"{len(data) / 1024:.0f} KB"
    c1, c2 = st.columns([5, 1])
    c1.markdown(f"📄 **{name}** · {suffix.lstrip('.').upper()} · {size}")
    c2.button("✕ Remove", on_click=clear_selection, width="stretch")

    if is_image:
        st.image(data, caption=name)
    elif is_text:
        with st.expander("Preview", expanded=False):
            st.text(data.decode("utf-8", errors="replace")[:5000])  # st.text never renders HTML/markdown
    else:
        st.write("PDF selected. Text and diagram pages will be extracted on analysis.")

    problems = []
    if mode == MODE_OFFLINE and is_image:
        problems.append("Offline mode cannot read diagram images. Choose an AI mode above, or upload a text/Markdown/PDF document.")
    if no_key:
        problems.append(f"{provider_label} is not configured. {provider_hint} See .env.example, or switch to Offline mode.")
    if mode == MODE_OFFLINE and is_text and not problems:
        try:  # cheap, local check so users know what offline mode will see before running
            found = extract_architecture(data.decode("utf-8", errors="replace"))
            names = ", ".join(c.name for c in found.components[:8])
            more = f" +{len(found.components) - 8} more" if len(found.components) > 8 else ""
            st.success(f"Quick scan: {len(found.components)} components detected ({names}{more}).")
        except LLMError as exc:
            problems.append(str(exc))
    for problem in problems:
        st.warning(problem)

    project = st.text_input("Project name", key="project_name", placeholder=default_project(name))
    content_key = hashlib.sha1(data).hexdigest()
    draft = st.session_state.get("draft")
    if draft and draft["key"] != content_key:  # a different file or text was selected
        st.session_state.pop("draft", None)
        draft = None

    left, right = st.columns([3, 2])
    if left.button(f"Analyze Architecture · {MODE_LABELS[mode]}", type="primary", disabled=bool(problems),
                   width="stretch"):
        run_analysis(name, data, project or default_project(name), mode)
    if right.button("Review components first", disabled=bool(problems), width="stretch", type="tertiary",
                    help="Detect components and flows, edit them, then run the analysis on your corrected version."):
        start_review(name, data, mode, content_key)
        draft = st.session_state.get("draft")

    if draft:
        st.subheader("4 · Review the detected architecture")
        edited = arch_editor.render(draft["id"], draft["arch"])
        if st.button("Discard review", key="discard_review"):
            st.session_state.pop("draft", None)
            st.rerun()
        if edited is not None:
            run_analysis(name, data, project or default_project(name), mode, architecture=edited, processed=draft["processed"])


def page_reports(model) -> None:
    st.title("Reports")
    st.warning("Exports contain generated, unverified findings. Review before sharing.")
    counts = {sev: sum(t.severity == sev for t in model.threats) for sev in ("Critical", "High", "Medium", "Low")}
    with st.container(border=True):
        st.markdown(f"**{model.project_name}**  ·  {model.source_filename}  ·  {model.generated_at.replace('T', ' ')}")
        m = st.columns(6)
        for col, (label, value) in zip(m, [
            ("Components", len(model.architecture.components)), ("Threats", len(model.threats)),
            ("Abuse cases", len(model.abuse_cases)), ("Controls", len(model.controls)),
            ("Test cases", len(model.test_cases)),
            ("Critical + High", counts["Critical"] + counts["High"])]):
            col.metric(label, value)
        render_review_progress(model)
        unreviewed = sum(t.review_status == "Unreviewed" for t in model.threats)
        if unreviewed:
            st.caption(f"{unreviewed} threat(s) are still unreviewed. You can export now, or review them first on "
                       "the **Threat Analysis** page. Review status is included in the JSON export.")
    left, right = st.columns(2)
    with left:
        st.markdown("**PDF report**  \nCover, executive summary, architecture, threats, abuse cases, controls and tests.")
        if st.button("Generate PDF report", width="stretch"):
            with st.spinner("Building PDF..."):
                st.session_state["pdf_bytes"] = build_pdf(model)
        if "pdf_bytes" in st.session_state:
            st.download_button("⬇ Download PDF", st.session_state["pdf_bytes"], "threat_model_report.pdf",
                               "application/pdf", type="primary", width="stretch")
    with right:
        st.markdown("**JSON export**  \nThe complete result including review status, for other tools or later comparison.")
        st.download_button(
            "⬇ Download JSON export", model.model_dump_json(indent=2), "threat_model.json", "application/json",
            width="stretch",
        )


def page_welcome() -> None:
    st.title("ThreatLens")
    st.markdown("##### Turn an architecture diagram or design document into a STRIDE threat model, "
                "abuse cases, security controls and test cases.")
    st.button("Upload Architecture →", key="welcome_upload", type="primary", on_click=go_to,
              args=("Upload Architecture",))


def sidebar() -> str:
    has_model = st.session_state.get("model") is not None
    if "nav" not in st.session_state:
        st.session_state["nav"] = "Dashboard"
    with st.sidebar:
        st.caption("AI-assisted STRIDE architecture reviews")
        for group, items in NAV_GROUPS:
            st.caption(group.upper())
            for page, icon in items:
                locked = not (has_model or page in ALWAYS_AVAILABLE)
                st.button(
                    f"{'🔒' if locked else icon}  {page}", key=f"nav_{page}", width="stretch",
                    type="primary" if st.session_state["nav"] == page else "secondary",
                    disabled=locked, on_click=go_to, args=(page,),
                    help="Run an analysis first to unlock this page." if locked else None,
                )
        if not has_model:
            st.caption("Run an analysis to unlock results, outputs and evaluation.")
        model = st.session_state.get("model")
        if model:
            counts = {sev: sum(t.severity == sev for t in model.threats) for sev in ("Critical", "High", "Medium", "Low")}
            with st.container(border=True):
                st.markdown(f"**{model.project_name}**")
                st.caption(f"{len(model.threats)} threats · " + "  ".join(
                    f"{SEV_ICON[k]} {v}" for k, v in counts.items() if v))
                st.caption(f"{MODE_LABELS.get(model.analysis_mode, model.analysis_mode)} · {model.llm_model}")
                st.button("＋ New analysis", key="new_analysis", on_click=go_to, args=("Upload Architecture",),
                          width="stretch")
        st.divider()
        ready, provider_label, provider_hint = ai_status()
        if ready:
            st.success(f"Claude via {provider_label} configured", icon="🔑")
        else:
            st.warning(f"{provider_label} not configured: only Offline mode is available", icon="🔑")
            if provider_hint:
                st.caption(provider_hint)
        model = st.session_state.get("model")
        if model and model.analysis_mode:
            st.caption(f"Current analysis: {MODE_LABELS.get(model.analysis_mode, model.analysis_mode)}")
        st.caption("Findings are generated automatically and require human review.")
    return st.session_state["nav"]


def main() -> None:
    page = sidebar()
    model = st.session_state.get("model")

    if page == "Upload Architecture":
        page_upload()
    elif page == "Dashboard":
        if model is None:
            page_welcome()
        else:
            if st.session_state.pop("toast_done", False):
                st.toast("Analysis complete: results are below", icon="✅")
            overview.render(model, after_title=last_run_banner)
    elif model is None:
        st.title(page)
        st.info("Analyze an architecture first (Upload Architecture page).")
    elif page == "Architecture Analysis":
        architecture.render(model)
    elif page == "Threat Analysis":
        threats.render(model)
    elif page == "Abuse Cases":
        findings.render_abuse_cases(model)
    elif page == "Security Controls":
        findings.render_controls(model)
    elif page == "Security Testing":
        findings.render_tests(model)
    elif page == "Reports":
        page_reports(model)
    elif page == "Manual vs AI":
        comparison.render(model)


main()
