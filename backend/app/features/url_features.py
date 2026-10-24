"""
Lexical / structural feature extraction from a raw URL string.

These are the hand-crafted features fed into the baseline models
(Random Forest / XGBoost / SVM) and used as auxiliary signal for the
adaptive fusion layer. Kept dependency-free (stdlib only) so it can
run identically at train time and at inference time.

NOTE on scope: every feature here is computed from the HOST/scheme
portion of the URL only -- none look at the path or query string.
This is deliberate, not an oversight: the real training corpus's
legitimate class (PhiUSIIL) is a domain-level dataset -- 0% of its
~135k legitimate URLs have any path, query string, or fragment at
all, while a large share of the phishing corpus does. Any feature
that can only be nonzero when a path/query exists (path length,
query-param count, path-scoped word matching, whole-URL length) is
therefore a proxy for "which dataset did this come from", not a
genuine phishing signal -- and it silently flags every real login
page, checkout flow, or search-result URL on the internet (verified:
a real Netflix post-login redirect URL, `netflix.com/in/login?nextpage=...`,
scored 99%+ malicious from this exact bias before the fix). Fabricating
legitimate deep-link URLs to counter this would itself be synthetic
training data, so the fix is scope discipline instead: only extract
signal from the part of the URL (host + scheme) where real, balanced
examples of both classes actually exist in the corpus. See the
README's "Known limitations" for what this trades away.

ONE deliberate exception: `malformed_query_syntax` (raw URL contains
more than one `?`). This is NOT "has a path/query" -- it's a raw
syntax check that a real, well-formed URL essentially never triggers.
Well-formed query strings use `&` to join multiple parameters after a
single `?` (`?a=1&b=2`); browsers, servers, and every standard web
framework produce exactly one `?`. A second `?` (e.g.
`/login?ogin?nextpage=https%3A%2F%2F...`) means the URL was
hand-constructed or mutated, not generated normally -- caught a real
case exactly like this (a crafted netflix.com URL with a malformed,
doubled query string smuggling an encoded redirect target) scoring as
clean under the host-only feature set alone. Checked this doesn't
reintroduce the bias above: none of the real branded URLs in
datasets/hard_negatives.csv, and no standard OAuth/SSO/post-login
redirect pattern (`?next=`, `?returnUrl=`, `?redirect_uri=`, all of
which use a single `?`), trigger it -- it fires specifically on
malformed syntax, not on redirects or paths in general.
"""
import re
import math
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "secure", "account", "update", "login", "signin", "verify",
    "banking", "confirm", "password", "wallet", "suspend", "unlock",
    "recover", "support", "authenticate", "invoice", "billing",
    "gift", "bonus", "free", "click", "urgent",
]

BRAND_TOKENS = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook",
    "netflix", "bankofamerica", "chase", "wellsfargo", "instagram",
    "whatsapp", "outlook", "dropbox", "linkedin",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _suspicious_word_count(host_lower: str) -> int:
    """Exact-token match, not substring containment. Substring
    matching was a real, verified bug: "accounts.google.com" (a
    completely standard, extremely common real login-portal subdomain
    pattern -- Google, Microsoft, Spotify, and most SaaS providers all
    use it) contains "account" as a raw substring, so it tripped this
    feature and helped push a genuine Google URL to a 55.8/100
    "suspicious" score. Splitting the host into dot/hyphen-separated
    tokens and requiring an exact match still catches the realistic
    phishing pattern (a hyphen-joined domain like
    "secure-login-verify-account.tk" tokenizes to ["secure", "login",
    "verify", "account", "tk"] -- "login" and "account" still match
    exactly) while no longer matching unrelated words that merely
    contain one as a substring ("accounting", "confirmation", etc.).
    Residual ambiguity, not fully resolved: "account" or "login" used
    as a real subdomain's OWN exact token (accounts.google.com,
    account.microsoft.com) still matches once, because that pattern is
    genuinely used by both real login portals and phishing sites --
    telling those apart needs the brand/trust signal in
    _brand_token_count, not this feature alone."""
    tokens = set(t for t in re.split(r"[.\-]", host_lower) if t)
    return sum(1 for w in SUSPICIOUS_WORDS if w in tokens)


def _brand_token_count(host: str) -> int:
    """Counts brand-name mentions in the host that look like
    impersonation, not the brand's own domain. A domain's second-level
    label (e.g. "netflix" in "www.netflix.com") exactly matching a
    brand token is the brand's real site, not a threat signal -- flag
    it, and every branded site in the world scores as "impersonating
    itself". Still flags the actual impersonation patterns: the token
    embedded in a longer SLD ("netflix-login.com"), or used as a
    subdomain in front of an unrelated real domain
    ("netflix.security-update.tk")."""
    labels = [p for p in host.split(".") if p]
    sld = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    host_compact = host.replace(".", "")
    return sum(1 for token in BRAND_TOKENS if token != sld and token in host_compact)


def extract_url_features(raw_url: str) -> dict:
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    host_lower = host.lower()

    labels = [p for p in host.split(".") if p]
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    features = {
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_underscores": host.count("_"),
        "num_digits": sum(c.isdigit() for c in host),
        "has_https": int(parsed.scheme == "https"),
        "has_ip_host": int(is_ip),
        "has_at_symbol": int("@" in url),
        "has_port": int(parsed.port is not None),
        "subdomain_count": max(0, len(labels) - 2) if not is_ip else 0,
        "tld_length": len(labels[-1]) if labels else 0,
        "suspicious_word_count": _suspicious_word_count(host_lower),
        "brand_token_count": _brand_token_count(host),
        "is_shortened": int(host in SHORTENERS),
        "host_entropy": round(_shannon_entropy(host), 4),
        "digit_ratio": round(sum(c.isdigit() for c in host) / max(1, len(host)), 4),
        "hyphen_in_host": int("-" in host),
        "long_host": int(len(host) > 30),
        "punycode": int(host.startswith("xn--") or ".xn--" in host),
        "malformed_query_syntax": int(url.count("?") > 1),
    }
    return features


def feature_vector(raw_url: str) -> tuple[list[float], list[str]]:
    """Returns (values, ordered_feature_names) for model input."""
    feats = extract_url_features(raw_url)
    names = sorted(feats.keys())
    return [float(feats[n]) for n in names], names


FEATURE_NAMES = sorted(extract_url_features("http://example.com/").keys())
