"""
Turns a URL into a "semantic" token stream so the Transformer encoder
has something resembling language to work with -- splitting on
non-alphanumerics and camel/word boundaries the way a human reading
`secure-paypal-login.com` would parse it into "secure paypal login".
"""
import re

_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def url_to_tokens(raw_url: str, max_tokens: int = 32) -> list[str]:
    cleaned = re.sub(r"^[a-zA-Z]+://", "", raw_url.strip())
    cleaned = cleaned.split("?")[0]
    pieces = [p for p in _SPLIT_RE.split(cleaned) if p]
    tokens: list[str] = []
    for piece in pieces:
        for sub in _CAMEL_RE.split(piece):
            if sub:
                tokens.append(sub.lower())
    return tokens[:max_tokens] if tokens else ["<empty>"]


def url_to_text(raw_url: str) -> str:
    return " ".join(url_to_tokens(raw_url))
