# ThreatLens

AI-powered threat modeling for architecture reviews. Upload an architecture diagram (PNG/JPG), PDF or design document (TXT/MD). The agent uses Claude to extract the
architecture, run a STRIDE analysis, write abuse cases, map controls to OWASP / ASVS / MITRE ATT&CK / NIST CSF,
generate security test cases, and export a PDF + JSON report. Built with Streamlit, LangGraph and Pydantic.

> All output is AI-generated and **unverified until a security engineer reviews it**. Recommended controls are not
> evidence that a control exists. Security tests are documentation only and are never executed by the app.

> **Developers:** see [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) for what each file does, the end-to-end flow, the data model and how to extend the app. Diagrams: [architecture](docs/diagrams/architecture.svg) and [flow](docs/diagrams/flow.svg).

## Workflow

```
Upload -> validate/process (PyMuPDF, Pillow, OpenCV) -> Architecture Analyzer -> STRIDE threats (risk engine)
       -> Abuse cases -> Control mapping -> Security tests -> Dashboard -> PDF / JSON report
```

Each agent in `agents/` is an independent function `run(llm, ...)`. `core/workflow.py` wires them with LangGraph
(falls back to a sequential runner if LangGraph is missing). Every LLM response is validated against Pydantic models in
`core/schemas.py` and retried (with the validation error fed back) up to 2 times.

Severity is **not** taken from the LLM: it proposes likelihood and impact (1-5) and `core/risk_engine.py` computes
`score = likelihood x impact` (Critical >= 20, High 12-19, Medium 6-11, Low <= 5).

## Analysis modes

Choose a mode on the **Upload Architecture** page before analysing:

| Mode | Needs AI provider | Notes |
|---|---|---|
| Offline (no API) | no | Keyword detection + local knowledge base (`knowledge/catalog.json`). Text/Markdown/PDF only, no diagram images. Output is generic and deterministic. |
| AI (Claude) | yes | Claude analyses the material directly (images supported). |
| AI + knowledge base (RAG) | yes | Claude, with matching threat patterns and controls from the catalog added to each prompt. |

All modes share the same schemas, risk engine and review flags. Extend offline coverage by editing the catalog JSON.

## Providing the architecture

On **Upload Architecture** (step 2) choose one of: **Upload a file** (PNG/JPG diagram, PDF, TXT/MD), **Paste details** (type or paste a description of your components and connections, then *Use this text*) or **Try the sample**. Pasted text goes through the same validation and untrusted-data handling as an uploaded document, so it works in every analysis mode.

## Reviewing the detected architecture

After choosing a file, **Analyze Architecture** runs everything at once. **Review components first** runs only the architecture stage and shows editable tables of components (name, type, trust boundary, sensitive data) and data flows (source, destination, protocol, authentication). Rename or delete wrong detections, add missing items, then **Run analysis with these edits**; the threat analysis uses exactly your corrected architecture. This matters most in Offline mode, where detection is keyword-based.

The sidebar groups pages (Home, Setup, Results, Outputs, Evaluate); result pages stay disabled until an analysis exists.

## Installation

Requires Python 3.11+.

```bash
cd ThreatLens
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

On Debian/Ubuntu you may first need `sudo apt install python3-venv python3-pip`.

## Environment variables

```bash
cp .env.example .env     # then edit .env
```

| Variable | Required | Default |
|---|---|---|
| `LLM_PROVIDER` | no | `anthropic` (also `bedrock`, `foundry`) |
| `ANTHROPIC_API_KEY` | `anthropic` provider | - |
| `AWS_REGION` + AWS credentials (or `AWS_BEARER_TOKEN_BEDROCK`) | `bedrock` provider | - |
| `ANTHROPIC_FOUNDRY_RESOURCE` + `ANTHROPIC_FOUNDRY_API_KEY` (or `ANTHROPIC_FOUNDRY_AUTH=entra`) | `foundry` provider | - |
| `LLM_MODEL` | no | `claude-sonnet-5-5` (Bedrock: `anthropic.claude-sonnet-5-5`; Foundry: your deployment name) |
| `ANTHROPIC_MODEL` | no | legacy name, applies to the `anthropic` provider only |
| `LOG_LEVEL` | no | `INFO` |

The key is read only from the environment; `.env` is git-ignored.

### Using Amazon Bedrock or Microsoft Foundry instead of the Anthropic API

Set `LLM_PROVIDER` and the matching settings from `.env.example`; nothing else changes (modes, methodology and
reports are identical). Bedrock needs the model enabled for your account in the chosen region (`pip install boto3`
for profiles, SSO or IAM roles). Foundry needs a Claude deployment in your Foundry resource; set `LLM_MODEL` to its
deployment name (`pip install azure-identity` for Microsoft Entra ID sign-in). Reports record the provider next to the
model name. The provider switch is covered by unit tests with stub clients; verify it once against your real account.

## Run

```bash
streamlit run app.py          # open http://localhost:8501
pytest                        # unit tests (no network, no API key needed)
```

## Demo (about 3 minutes)

1. Open **Upload Architecture** -> click *Try: Design document (Markdown)* in the sample box
   (and/or the PNG diagram, generated on demand with Pillow) -> **Analyze Architecture**.
2. **Dashboard**: summary cards, risk distribution, recent findings.
3. **Architecture Analysis**: data-flow diagram; dashed items are inferred/uncertain and need review.
4. **Threat Analysis**: filter by severity/component/STRIDE, sort, click a row, set its review status.
5. **Abuse Cases**, **Security Controls**, **Security Testing**.
6. **Reports**: download PDF and JSON.
7. **Manual vs AI**: paste your own threat list (`title | component | STRIDE`), enter your manual review time, and
   compare. Regenerate the diagram manually with `python data/sample_architecture/generate_diagram.py`.

The sample document deliberately contains weaknesses (no MFA, token in local storage, unauthenticated webhook,
single over-privileged service account, plaintext HTTP internally, no admin audit logging) so there is something to find.

## Security design

- File type, size and magic-byte validation; uploads are parsed in memory, never executed or saved to disk.
- Images are re-encoded from pixels (drops metadata/payloads); PDFs are only read with PyMuPDF.
- Uploaded content is wrapped in `<untrusted_document>` tags with a system prompt that treats it as data; a heuristic
  scanner warns when a document contains instruction-like phrases. This reduces, but cannot eliminate, prompt injection.
- Logs contain stage names, counts and validation error locations, never document content or model output.
- LLM-supplied text is HTML-escaped before display/PDF; review status is human-owned; control status is forced to
  "Recommended - not verified as implemented"; threats citing unknown components are flagged.

## Known limitations

- Document content and extracted architecture are sent to the Anthropic API; do not upload material you are not
  permitted to share with it.
- Diagram reading depends on image quality and labelling; the model can still misread or over-interpret. Review the
  items flagged `inferred` / `needs review`.
- Framework references (ASVS requirement IDs, ATT&CK technique IDs) are model-suggested and can be wrong; verify them.
- Likelihood/impact ratings are model estimates with no knowledge of your real controls or business context.
- STRIDE-per-component output is non-deterministic; two runs on the same input will differ.
- Manual-vs-AI matching is a word-overlap heuristic; use the matched-pairs table to verify it.
- Large PDFs: only the first 40 pages are read and at most 6 diagram-like pages are sent as images; text is capped at
  60,000 characters.
- State is held in the Streamlit session only: refreshing the browser loses the analysis (export JSON to keep it).
- No authentication or multi-user separation; deploy behind your own access controls.
- There is no way to re-import a JSON export yet.
