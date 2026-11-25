"""Fetch an architecture description from a URL (Confluence page or any public web page) as plain text.
The result is untrusted data like an upload: size-capped, converted to text, never executed.
"""
import ipaddress
import logging
import os
import re
import socket
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from processors.document_processor import MAX_FILE_BYTES, FileValidationError, safe_display_name

log = logging.getLogger("threat_agent.url_fetcher")

TIMEOUT_SECONDS = 20
MAX_REDIRECTS = 3
BLOCK_TAGS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "table", "section", "ul", "ol"}
SKIP_TAGS = {"script", "style", "noscript", "svg", "head"}


class UrlFetchError(FileValidationError):
    """The URL could not be fetched; the message is safe to show to the user."""


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True
        if tag in SKIP_TAGS - {"head"}:
            self._skip += 1
        if tag in BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "li":
            self.parts.append("- ")
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.parts.append("#" * int(tag[1]) + " ")
        if tag == "img":
            alt = dict(attrs).get("alt")
            if alt:
                self.parts.append(f"[image: {alt}]")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag in SKIP_TAGS - {"head"}:
            self._skip = max(0, self._skip - 1)
        if tag in BLOCK_TAGS or tag in {"td", "th"}:
            self.parts.append("\n" if tag != "td" and tag != "th" else " | ")

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> tuple[str, str]:
    """Returns (title, text)."""
    parser = _TextExtractor()
    parser.feed(html)
    text = "".join(parser.parts)
    text = re.sub(r"[ \t\xa0]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()
    return parser.title.strip(), text


def _check_public_host(host: str) -> None:
    """Refuse loopback, private and link-local targets so the fetcher cannot be pointed at internal services."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UrlFetchError(f"Could not resolve host '{host}'.") from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if not addr.is_global:
            raise UrlFetchError("That address points to a private or internal network and cannot be fetched.")


def _validate_url(url: str) -> str:
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise UrlFetchError("Enter a full https:// link.")
    if parsed.username or parsed.password:
        raise UrlFetchError("Do not put credentials in the link.")
    _check_public_host(parsed.hostname)
    return url


def _confluence_api_url(url: str) -> str | None:
    """Map a Confluence page link to its REST API URL, or None when it is not a recognisable page link."""
    parsed = urlparse(url)
    page_id = None
    match = re.search(r"/pages/(\d+)", parsed.path)
    if match:
        page_id = match.group(1)
    elif parse_qs(parsed.query).get("pageId"):
        page_id = parse_qs(parsed.query)["pageId"][0]
    if not page_id or not page_id.isdigit():
        return None
    base = f"{parsed.scheme}://{parsed.netloc}"
    prefix = "/wiki" if parsed.path.startswith("/wiki/") or parsed.netloc.endswith(".atlassian.net") else ""
    return f"{base}{prefix}/rest/api/content/{page_id}?expand=body.export_view,title"


def _auth_headers(url: str) -> dict:
    """Credentials come from .env and are only sent to the host named in CONFLUENCE_BASE_URL, so they can never
    be sent to an arbitrary site."""
    env_host = urlparse(os.environ.get("CONFLUENCE_BASE_URL", "")).hostname
    if not env_host or env_host.lower() != (urlparse(url).hostname or "").lower():
        return {}
    email, token = os.environ.get("CONFLUENCE_EMAIL", ""), os.environ.get("CONFLUENCE_API_TOKEN", "")
    if not token:
        return {}
    if email:  # Atlassian Cloud: email + API token
        import base64
        return {"Authorization": "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()}
    return {"Authorization": f"Bearer {token}"}  # Data Center / Server: personal access token


def _get(url: str, headers: dict) -> httpx.Response:
    """GET with a size cap and manually followed, re-validated redirects."""
    with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            url = _validate_url(url)
            try:
                with client.stream("GET", url, headers=headers) as resp:
                    if resp.is_redirect:
                        url = urljoin(url, resp.headers.get("location", ""))
                        headers = {}  # never forward credentials to a redirect target
                        continue
                    body = bytearray()
                    for chunk in resp.iter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_FILE_BYTES:
                            raise UrlFetchError(f"The page exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit.")
                    headers_out = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-encoding", "content-length")}
                    return httpx.Response(resp.status_code, headers=headers_out, content=bytes(body))  # already decoded
            except httpx.HTTPError as exc:
                raise UrlFetchError(f"Could not reach the link ({type(exc).__name__}).") from exc
    raise UrlFetchError("Too many redirects.")


def fetch_url(url: str) -> tuple[str, bytes]:
    """Returns (filename, utf-8 markdown bytes) ready to be treated like an uploaded text document."""
    url = _validate_url(url)
    api = _confluence_api_url(url)
    accept = {"Accept": "application/json" if api else "text/html,text/plain"}
    resp = _get(api or url, accept)  # public first: credentials are only used if the page turns out to be private
    if api and resp.status_code in (401, 403):
        headers = _auth_headers(url)
        if headers:
            resp = _get(api, {**headers, **accept})

    if resp.status_code in (401, 403):
        raise UrlFetchError("Access denied. For a private Confluence page, set CONFLUENCE_BASE_URL, CONFLUENCE_EMAIL "
                            "and CONFLUENCE_API_TOKEN in .env and restart the app.")
    if resp.status_code == 404:
        raise UrlFetchError("Page not found. Check the link, and that your account can open it.")
    if resp.status_code >= 400:
        raise UrlFetchError(f"The server answered with HTTP {resp.status_code}.")

    if api:
        try:
            data = resp.json()
            title = data.get("title", "")
            _, text = html_to_text(data["body"]["export_view"]["value"])
        except (ValueError, KeyError, TypeError) as exc:
            raise UrlFetchError("Unexpected response from Confluence. Is this a page link?") from exc
    else:
        ctype = resp.headers.get("content-type", "").lower()
        raw = resp.content.decode(resp.encoding or "utf-8", errors="replace")
        if "html" in ctype:
            title, text = html_to_text(raw)
        elif ctype.startswith("text/"):
            title, text = "", raw
        else:
            raise UrlFetchError(f"Unsupported content type '{ctype or 'unknown'}'. Use a web page or a text link.")

    if len(text) < 20:
        raise UrlFetchError("The page has no readable text. A page that needs sign-in may return a login screen.")
    log.info("fetched url kind=%s chars=%d", "confluence" if api else "web", len(text))
    name = safe_display_name(f"{title or urlparse(url).hostname}.md")
    return name, (f"# {title}\n\n{text}" if title else text).encode("utf-8")
