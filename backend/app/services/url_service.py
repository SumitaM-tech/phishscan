import re
from urllib.parse import urlparse, urlunparse


def normalize_url(raw: str) -> str | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        # No scheme given (e.g. a bare "github.com" typed into the
        # investigate box). Default to https, matching what modern
        # browsers do and how virtually all real legitimate traffic
        # actually looks today -- defaulting to http here would make
        # every scheme-less legitimate query look like it's missing
        # TLS, which is exactly the kind of signal the model uses to
        # spot phishing (see the README's "real bug" notes).
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        if not parsed.hostname:
            return None
        if parsed.scheme not in ("http", "https"):
            return None
        netloc = parsed.hostname.lower()
        if parsed.port:
            netloc += f":{parsed.port}"
        path = parsed.path or "/"
        normalized = urlunparse((parsed.scheme, netloc, path, "", parsed.query, ""))
        return normalized
    except Exception:  # noqa: BLE001
        return None


def get_hostname(url: str) -> str:
    return urlparse(url).hostname or ""
