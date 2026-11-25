"""Upload validation and extraction. Uploads are untrusted: they are parsed as data, never executed,
never written to disk, and their content is never logged.
"""
import logging
import re
from pathlib import Path

from core.schemas import ProcessedInput

log = logging.getLogger("threat_agent.processor")

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TEXT_CHARS = 60_000
MAX_PDF_PAGES = 40
MAX_PDF_RENDERED_PAGES = 6

ALLOWED_EXTENSIONS = {
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".pdf": "pdf",
    ".txt": "text",
    ".md": "text",
    ".markdown": "text",
}
MAGIC = {"png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff", "pdf": b"%PDF-"}

INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?)",
    r"disregard (all |any |the )?(previous|prior|above)",
    r"\byou are now\b",
    r"\bpretend to be\b",
    r"system prompt",
    r"reveal (your|the) (instructions|prompt)",
    r"do not (report|list|mention) (any )?(threats|vulnerabilit)",
    r"new instructions?:",
]


class FileValidationError(ValueError):
    """Upload rejected; the message is safe to show to the user."""


def safe_display_name(filename: str) -> str:
    name = Path(filename or "upload").name
    return re.sub(r"[^\w.\- ()]", "_", name)[:100] or "upload"


def validate_upload(filename: str, data: bytes) -> str:
    """Check extension, size and magic bytes. Returns kind: image | pdf | text."""
    ext = Path(filename or "").suffix.lower()
    kind = ALLOWED_EXTENSIONS.get(ext)
    if kind is None:
        raise FileValidationError(f"Unsupported file type '{ext or 'unknown'}'. Use PNG, JPG, PDF, TXT or MD.")
    if not data:
        raise FileValidationError("The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise FileValidationError(f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit.")

    if ext == ".png" and not data.startswith(MAGIC["png"]):
        raise FileValidationError("File content is not a PNG image.")
    if ext in (".jpg", ".jpeg") and not data.startswith(MAGIC["jpg"]):
        raise FileValidationError("File content is not a JPEG image.")
    if ext == ".pdf" and not data[:1024].lstrip().startswith(MAGIC["pdf"]):
        raise FileValidationError("File content is not a PDF document.")
    if kind == "text" and b"\x00" in data[:4096]:
        raise FileValidationError("File looks binary, not a text document.")
    return kind


def scan_for_injection(text: str) -> list[str]:
    """Heuristic detector. It only warns the user; the real defence is delimiting content as data."""
    hits = [p for p in INJECTION_PATTERNS if re.search(p, text, flags=re.IGNORECASE)]
    if not hits:
        return []
    return [
        "The document contains phrases that look like instructions to an AI model "
        f"({len(hits)} pattern(s) matched). They will be treated as plain data, but review the results carefully."
    ]


def _truncate(text: str, warnings: list[str]) -> str:
    if len(text) > MAX_TEXT_CHARS:
        warnings.append(f"Text truncated to the first {MAX_TEXT_CHARS:,} characters.")
        return text[:MAX_TEXT_CHARS]
    return text


def _process_image(name: str, data: bytes) -> ProcessedInput:
    from processors.image_processor import ImageValidationError, normalize_image

    try:
        payload, warnings = normalize_image(data, description=name)
    except ImageValidationError as exc:
        raise FileValidationError(str(exc)) from exc
    return ProcessedInput(filename=name, kind="image", size_bytes=len(data), images=[payload], warnings=warnings)


def _process_pdf(name: str, data: bytes) -> ProcessedInput:
    import fitz  # PyMuPDF

    from processors.image_processor import ImageValidationError, normalize_image

    warnings: list[str] = []
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:
        raise FileValidationError("Could not open the PDF (corrupt or unsupported).") from exc
    try:
        if doc.needs_pass:
            raise FileValidationError("Password-protected PDFs are not supported.")
        pages = min(doc.page_count, MAX_PDF_PAGES)
        if doc.page_count > MAX_PDF_PAGES:
            warnings.append(f"Only the first {MAX_PDF_PAGES} of {doc.page_count} pages were read.")

        chunks, images = [], []
        for index in range(pages):
            page = doc[index]
            page_text = page.get_text("text") or ""
            chunks.append(f"--- Page {index + 1} ---\n{page_text}")
            # Render pages that likely contain diagrams (images, vector drawings, or almost no text).
            visual = len(page.get_images()) > 0 or len(page.get_drawings()) > 20 or len(page_text.strip()) < 200
            if visual and len(images) < MAX_PDF_RENDERED_PAGES:
                png = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5)).tobytes("png")
                try:
                    payload, _ = normalize_image(png, description=f"{name} page {index + 1}")
                    images.append(payload)
                except ImageValidationError:
                    warnings.append(f"Page {index + 1} could not be rendered.")
        text = _truncate("\n".join(chunks), warnings)
        if not text.strip() and not images:
            raise FileValidationError("No readable content found in the PDF.")
        if len(images) == MAX_PDF_RENDERED_PAGES:
            warnings.append(f"Only the first {MAX_PDF_RENDERED_PAGES} diagram-like pages were sent as images.")
        return ProcessedInput(
            filename=name, kind="pdf", size_bytes=len(data), text=text, images=images,
            warnings=warnings, page_count=doc.page_count,
        )
    finally:
        doc.close()


def _process_text(name: str, data: bytes) -> ProcessedInput:
    warnings: list[str] = []
    text = _truncate(data.decode("utf-8", errors="replace"), warnings)
    if not text.strip():
        raise FileValidationError("The document has no text.")
    return ProcessedInput(filename=name, kind="text", size_bytes=len(data), text=text, warnings=warnings)


def process_upload(filename: str, data: bytes) -> ProcessedInput:
    kind = validate_upload(filename, data)
    name = safe_display_name(filename)
    log.info("processing upload kind=%s size=%d", kind, len(data))  # never log name or content
    result = {"image": _process_image, "pdf": _process_pdf, "text": _process_text}[kind](name, data)
    result.warnings.extend(scan_for_injection(result.text))
    return result
