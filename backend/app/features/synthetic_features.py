"""
Extended URL feature set used by the SYNTHETIC-trained models.

The original feature extractor (`url_features.py`) is intentionally left
untouched: the original real-data models (artifacts/rf.pkl, xgboost.pkl,
svm.pkl) were trained on exactly those 20 host-only features and are kept
as the backup scorer, so their input contract must not change.

The synthetic dataset (datasets/synthetic/) is generated with realistic
paths, queries and legitimate deep-links on BOTH classes, so the dataset
bias that forced the original features to ignore the path does not exist
there. That lets this module add path/query/brand-ownership signals on
top of the original 20 host features:

  * brand ownership   -- is a brand named in the URL while the registrable
                         domain is NOT one of that brand's official domains
  * typosquatting     -- leetspeak / edit-distance matches to known brands
  * path lures        -- exact-token lure words, script extensions, brand
                         names, encoded redirect targets, long hex tokens
  * host shape        -- SLD randomness, cheap TLDs, free-hosting platforms,
                         private/raw IP hosts, punycode, userinfo tricks

Stdlib only, so train time and inference time are identical.
"""
import math
import re
from urllib.parse import urlparse, parse_qsl, unquote

from app.features.url_features import extract_url_features

# --- brand knowledge --------------------------------------------------
# brand token -> set of OFFICIAL registrable domains for that brand.
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"},
    "google": {"google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com", "googleusercontent.com", "googlevideo.com", "ggpht.com", "withgoogle.com", "g.co", "goo.gl", "googlesyndication.com", "google-analytics.com", "googletagmanager.com"},
    "apple": {"apple.com", "icloud.com", "mzstatic.com", "icloud-content.com", "cdn-apple.com"},
    "icloud": {"icloud.com", "apple.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com", "windows.com", "microsoft365.com", "sharepoint.com", "onedrive.com", "azure.com", "windowsazure.com", "msn.com", "bing.com", "skype.com", "office365.com", "msauth.net", "msftauth.net"},
    "office365": {"office.com", "microsoft.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "office.com", "live.com", "microsoft.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon-adsystem.com", "primevideo.com", "audible.com", "media-amazon.com", "ssl-images-amazon.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com", "fbcdn.net", "facebook.net", "messenger.com", "fb.me"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"},
    "bankofamerica": {"bankofamerica.com"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citibank.com", "citi.com"},
    "capitalone": {"capitalone.com"},
    "americanexpress": {"americanexpress.com", "aexp.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.co.in"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com", "dropboxapi.com", "dropbox.tech"},
    "linkedin": {"linkedin.com", "licdn.com", "lnkd.in"},
    "adobe": {"adobe.com", "adobe.io", "adobelogin.com", "adobesign.com", "typekit.net"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "ups": {"ups.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com", "steam-chat.com"},
    "spotify": {"spotify.com", "scdn.co", "spotifycdn.com"},
    "twitter": {"twitter.com", "x.com", "twimg.com", "t.co"},
    "yahoo": {"yahoo.com", "yimg.com", "yahoo.co.jp"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebaystatic.com", "ebay.in", "ebay.de"},
    "walmart": {"walmart.com"},
    "zoom": {"zoom.us", "zoom.com", "zoomgov.com"},
    "github": {"github.com", "github.io", "githubusercontent.com", "githubassets.com", "github.dev"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "paytm": {"paytm.com"},
    "irs": {"irs.gov"},
    "att": {"att.com"},
    "verizon": {"verizon.com"},
}
BRANDS = sorted(BRAND_DOMAINS)
_ALL_OFFICIAL = set().union(*BRAND_DOMAINS.values())

# Brand tokens short/ambiguous enough that substring matching is noisy;
# these only count on exact label/token matches.
_SHORT_BRANDS = {"att", "ups", "irs", "sbi", "dhl", "hsbc", "zoom", "steam", "chase", "apple", "adobe", "yahoo", "ebay"}

TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "gov.in", "ac.in", "net.in", "org.in", "com.au",
    "edu.au", "gov.au", "co.nz", "co.jp", "co.za", "com.br", "com.mx", "com.tr", "com.cn", "com.sg",
    "co.kr", "com.pk", "com.bd", "com.ng", "com.ar",
}

FREE_HOSTING = (
    "weebly.com", "weeblysite.com", "web.app", "firebaseapp.com", "repl.co", "wixsite.com",
    "blogspot.com", "github.io", "netlify.app", "vercel.app", "herokuapp.com", "000webhostapp.com",
    "glitch.me", "surge.sh", "pages.dev", "workers.dev", "sites.google.com", "azurewebsites.net",
    "wordpress.com", "godaddysites.com", "myshopify.com", "webflow.io", "framer.app", "carrd.co",
    "webcindario.com", "wasmer.app", "wixstudio.com", "wixsite.com", "sviluppo.host", "weeblysite.com",
)

CHEAP_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support", "buzz", "icu", "cfd",
    "sbs", "rest", "monster", "cyou", "quest", "live", "site", "online", "shop", "link", "vip",
    "zip", "mov", "su", "pw", "cc", "ws", "bid", "loan", "country", "stream", "download", "men",
}
COMMON_TLDS = {"com", "org", "net", "edu", "gov", "io", "co", "in", "uk", "de", "fr", "ca", "au", "jp"}

LURE_WORDS = {
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "password", "passwd", "banking", "wallet", "suspend", "suspended", "unlock",
    "recover", "recovery", "authenticate", "billing", "invoice", "payment", "validate", "restore",
    "alert", "limited", "reactivate", "resolve", "webscr", "cmd", "token", "auth", "credential",
    "credentials", "payroll", "voicemail", "shipment", "tracking", "refund", "claim", "prize",
    "gift", "bonus", "urgent", "expire", "expired", "helpdesk", "support",
}
SCRIPT_EXT = {"php", "asp", "aspx", "jsp", "cgi", "exe", "scr", "apk", "zip", "rar", "jar", "bat", "js", "htm", "html"}
DANGEROUS_EXT = {"exe", "scr", "apk", "zip", "rar", "jar", "bat"}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "s.id", "v.gd",
    "qrco.de", "l.ead.me", "qr-codes.io", "hotm.art", "mkls.in", "linktr.ee", "t.ly", "short.io",
}

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"})


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def _edit_distance(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable_domain(host: str) -> str:
    labels = [p for p in host.lower().split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def _is_private_ip(host: str) -> bool:
    if not _is_ip(host):
        return False
    a, b = (int(x) for x in host.split(".")[:2])
    return a == 10 or a == 127 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _brand_in(tokens: list[str], compact: str) -> set[str]:
    """Brands mentioned in a token list. Short/ambiguous brands need an
    exact token match; long distinctive ones also match as substrings of
    the compacted text (catches 'paypalsecure', 'netflix-login')."""
    found = set()
    for b in BRANDS:
        if b in _SHORT_BRANDS:
            if b in tokens:
                found.add(b)
        elif b in tokens or b in compact:
            found.add(b)
    return found


def _owns(registrable: str, brand: str) -> bool:
    return registrable in BRAND_DOMAINS[brand] or any(registrable.endswith("." + d) for d in BRAND_DOMAINS[brand])


def _query_redirect_cross_domain(query: str, host_reg: str) -> tuple[int, int]:
    """(has_url_in_query, that_url_points_to_a_different_registrable_domain)"""
    has_url = cross = 0
    for _, v in parse_qsl(query, keep_blank_values=True):
        v = unquote(v)
        m = re.match(r"^(?:https?:)?//([^/\s?#]+)", v, re.I)
        if m:
            has_url = 1
            target = re.sub(r"^.*@", "", m.group(1)).split(":")[0]
            if registrable_domain(target) != host_reg:
                cross = 1
    if not has_url and re.search(r"(?i)(%3a%2f%2f|https?%3a)", query):
        has_url = 1
        cross = 1
    return has_url, cross


def extract_synthetic_features(raw_url: str) -> dict:
    base = extract_url_features(raw_url)  # the original 20 host features

    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    path = p.path or ""
    query = p.query or ""
    labels = [x for x in host.split(".") if x]
    reg = registrable_domain(host)
    reg_labels = reg.split(".")
    sld = reg_labels[0] if reg_labels else ""
    tld = labels[-1] if labels else ""
    is_ip = _is_ip(host)
    sub_labels = labels[: max(0, len(labels) - len(reg_labels))] if not is_ip else []

    path_tokens = _tokens(unquote(path))
    query_tokens = _tokens(unquote(query))
    host_tokens = _tokens(host)
    host_compact = host.replace(".", "").replace("-", "")
    sub_compact = "".join(sub_labels).replace("-", "")
    sld_norm = sld.translate(_LEET)

    brands_host = _brand_in(host_tokens, host_compact)
    brands_path = _brand_in(path_tokens + query_tokens, "".join(path_tokens + query_tokens))
    unofficial_host_brands = {b for b in brands_host if not _owns(reg, b)}
    unofficial_path_brands = {b for b in brands_path if not _owns(reg, b)}
    brands_sub = _brand_in(_tokens(".".join(sub_labels)), sub_compact)
    brand_in_subdomain_unofficial = {b for b in brands_sub if not _owns(reg, b)}

    host_leet = host.translate(_LEET)
    brands_host_leet = _brand_in(_tokens(host_leet), host_leet.replace(".", "").replace("-", "")) - brands_host if host_leet != host else set()
    leet_in_host = bool({b for b in brands_host_leet if not _owns(reg, b)})

    sld_exact_brand = sld in BRAND_DOMAINS
    brand_domain_official = int(reg in _ALL_OFFICIAL)
    brand_exact_unofficial = int(sld_exact_brand and not _owns(reg, sld))

    leet_match = int(leet_in_host or (bool(sld) and sld != sld_norm and sld_norm in BRAND_DOMAINS and not _owns(reg, sld_norm)))
    near_brand = 0
    if sld and len(sld) >= 5 and sld not in BRAND_DOMAINS and not leet_match:
        for b in BRANDS:
            if len(b) >= 5 and _edit_distance(sld_norm, b, 2) <= 1 and not _owns(reg, b):
                near_brand = 1
                break

    lure_path = sum(1 for w in LURE_WORDS if w in set(path_tokens) or w in set(query_tokens))
    lure_host = sum(1 for w in LURE_WORDS if w in set(host_tokens))

    last_seg = path.rsplit("/", 1)[-1].lower()
    ext = last_seg.rsplit(".", 1)[-1] if "." in last_seg else ""
    path_len = len(path)
    segs = [s for s in path.split("/") if s]
    redirect_has_url, redirect_cross = _query_redirect_cross_domain(query, reg)

    vowels = sum(c in "aeiou" for c in sld)
    letters = sum(c.isalpha() for c in sld)
    max_consonant_run = max((len(m.group(0)) for m in re.finditer(r"[^aeiou0-9\-]+", sld)), default=0)

    ext_feats = {
        "url_length": len(url),
        "path_length": path_len,
        "path_depth": len(segs),
        "query_length": len(query),
        "num_query_params": len(parse_qsl(query, keep_blank_values=True)),
        "path_lure_word_count": min(lure_path, 6),
        "host_lure_word_count": min(lure_host, 6),
        "path_brand_unofficial": int(bool(unofficial_path_brands)),
        "host_brand_unofficial": int(bool(unofficial_host_brands)),
        "subdomain_brand_unofficial": int(bool(brand_in_subdomain_unofficial)),
        "brand_exact_unofficial_domain": brand_exact_unofficial,
        "brand_official_domain": brand_domain_official,
        "leet_brand_match": leet_match,
        "near_brand_typosquat": near_brand,
        "path_script_ext": int(ext in SCRIPT_EXT and ext not in {"htm", "html", "js"}),
        "path_html_ext": int(ext in {"htm", "html"}),
        "path_dangerous_ext": int(ext in DANGEROUS_EXT),
        "path_digit_ratio": round(sum(c.isdigit() for c in path) / max(1, path_len), 4),
        "path_entropy": round(_entropy(path), 4),
        "has_url_in_query": redirect_has_url,
        "redirect_cross_domain": redirect_cross,
        "double_slash_in_path": int("//" in path),
        "long_hex_token": int(bool(re.search(r"[0-9a-fA-F]{24,}", path + query))),
        "sld_length": len(sld),
        "sld_entropy": round(_entropy(sld), 4),
        "sld_vowel_ratio": round(vowels / max(1, letters), 4),
        "sld_digit_ratio": round(sum(c.isdigit() for c in sld) / max(1, len(sld)), 4),
        "sld_max_consonant_run": max_consonant_run,
        "tld_cheap": int(tld in CHEAP_TLDS),
        "tld_common": int(tld in COMMON_TLDS or ".".join(labels[-2:]) in TWO_PART_SUFFIXES),
        "is_free_hosting": int(any(host == s or host.endswith("." + s) for s in FREE_HOSTING)),
        "is_private_ip": int(_is_private_ip(host)),
        "userinfo_in_netloc": int("@" in (p.netloc or "")),
        "nonstandard_port": int(p.port is not None and p.port not in (80, 443)),
        "known_shortener": int(host in SHORTENERS),
    }
    return {**base, **ext_feats}


def synthetic_feature_vector(raw_url: str) -> tuple[list[float], list[str]]:
    feats = extract_synthetic_features(raw_url)
    names = sorted(feats)
    return [float(feats[n]) for n in names], names


SYNTHETIC_FEATURE_NAMES = sorted(extract_synthetic_features("https://example.com/").keys())
