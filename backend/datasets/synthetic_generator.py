"""
Synthetic URL dataset generator.

Produces a labeled corpus of fully synthetic URLs (no real crawled or
feed data) for training/evaluating the PhishScan URL classifiers:

    python -m datasets.synthetic_generator              # 80k URLs, seed 42
    python -m datasets.synthetic_generator --n 120000 --seed 7

Output: datasets/synthetic/synthetic_urls.csv with columns
    url, label (1=phishing, 0=legitimate), category, split (train/val/test)

Design goals (so the classifier learns real signal, not generator quirks):

  * BOTH classes draw domain names from the SAME shared name generator
    and the same TLD/scheme pools. A phishing URL is not identifiable
    just because its domain "looks random" or "uses https".
  * Hard negatives on the legitimate side: real brands on their OFFICIAL
    domains with login/account/verify paths and ?continue=/?next=
    redirects, SaaS login portals, deep e-commerce/doc links, hex-hash
    asset paths, legit sites on cheap TLDs / free hosting / plain http,
    OAuth redirects, brand names in news slugs, legit shorteners.
  * Hard positives on the phishing side: clean-looking domains with only
    a lure in the path, https everywhere, compromised-site paths,
    typosquats, free-hosting abuse, @-tricks, punycode, malformed
    queries, open-redirect abuse, brand-exact domains on wrong TLDs.
  * Splits are DOMAIN-DISJOINT: every registrable domain lands entirely
    in train, val or test, so test accuracy measures generalization to
    unseen domains, not memorization.

Deterministic for a given --seed.
"""
import argparse
import random
import string
from pathlib import Path
from urllib.parse import quote

import pandas as pd

from app.features.synthetic_features import (
    BRAND_DOMAINS, FREE_HOSTING, SHORTENERS, registrable_domain,
)

OUT_DIR = Path(__file__).resolve().parent / "synthetic"
OUT_FILE = OUT_DIR / "synthetic_urls.csv"

# ---------------------------------------------------------------------
# vocab
# ---------------------------------------------------------------------
SYL = ["ba", "be", "bo", "ca", "co", "cu", "da", "de", "di", "do", "fa", "fi", "fo", "ga", "go", "ha", "he", "hi",
       "ja", "jo", "ka", "ki", "ko", "la", "le", "li", "lo", "lu", "ma", "me", "mi", "mo", "na", "ne", "ni", "no",
       "pa", "pe", "pi", "po", "ra", "re", "ri", "ro", "sa", "se", "si", "so", "su", "ta", "te", "ti", "to", "tu",
       "va", "ve", "vi", "vo", "wa", "we", "za", "zo", "lex", "tron", "dyn", "net", "soft", "tech", "mark", "gen",
       "ton", "ver", "ment", "port", "ware", "link", "star", "wave", "cloud", "data", "byte", "core", "flex"]
WORDS = ["blue", "green", "red", "bright", "swift", "north", "south", "east", "west", "peak", "river", "stone", "oak",
         "pine", "harbor", "summit", "pixel", "atlas", "nova", "orbit", "delta", "alpha", "vertex", "prime", "urban",
         "metro", "coastal", "valley", "ridge", "forge", "craft", "works", "labs", "studio", "group", "partners",
         "systems", "solutions", "digital", "global", "first", "united", "royal", "golden", "silver", "iron", "bay",
         "lake", "hill", "field", "garden", "bakery", "dental", "legal", "fitness", "travel", "foods", "motors",
         "realty", "design", "media", "health", "care", "energy", "logistics", "consulting", "capital", "finance",
         "insurance", "learning", "academy", "college", "institute", "university", "hospital", "clinic", "market"]
FIRST = ["john", "maria", "ahmed", "priya", "li", "carlos", "anna", "kofi", "sara", "david", "emma", "raj", "lucas"]

GOOD_TLDS = ["com"] * 22 + ["org"] * 4 + ["net"] * 4 + ["io"] * 3 + ["co"] * 2 + ["info", "biz", "us", "app", "dev", "ai", "me", "tv"]
CC_TLDS = ["co.uk", "de", "fr", "in", "co.in", "ca", "com.au", "nl", "es", "it", "jp", "br", "com.br", "se", "ch", "co.za", "sg", "com.sg"]
CHEAP = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support", "buzz", "icu", "cfd", "sbs", "rest",
         "monster", "cyou", "quest", "live", "site", "online", "shop", "link", "vip", "pw", "cc", "ws", "su"]
LEGIT_ODD_TLDS = ["xyz", "online", "site", "shop", "live", "link", "top", "cc", "ws"]  # legit sites DO use these

SUBS_LEGIT = ["www", "www", "www", "blog", "docs", "shop", "store", "mail", "support", "help", "app", "api", "cdn",
              "static", "news", "m", "careers", "portal", "learn", "status", "dev", "go", "my", "id", "auth", "accounts"]
LURE = ["secure", "login", "signin", "verify", "account", "update", "confirm", "banking", "password", "wallet",
        "suspended", "unlock", "recover", "support", "authenticate", "billing", "invoice", "validate", "restore",
        "alert", "limited", "reactivate", "resolve", "service", "customer", "online", "access", "id", "portal"]
BRANDS = sorted(BRAND_DOMAINS)

# brands with a clean, canonical official host for legit login pages
OFFICIAL_HOSTS = {
    "paypal": ["www.paypal.com", "paypal.com"], "google": ["accounts.google.com", "www.google.com", "myaccount.google.com", "mail.google.com", "drive.google.com"],
    "apple": ["appleid.apple.com", "www.apple.com", "support.apple.com", "icloud.com"],
    "microsoft": ["login.microsoftonline.com", "account.microsoft.com", "www.microsoft.com", "login.live.com", "outlook.office.com"],
    "amazon": ["www.amazon.com", "www.amazon.in", "www.amazon.co.uk", "sellercentral.amazon.com"],
    "facebook": ["www.facebook.com", "m.facebook.com", "business.facebook.com"],
    "instagram": ["www.instagram.com"], "whatsapp": ["web.whatsapp.com", "www.whatsapp.com"],
    "netflix": ["www.netflix.com", "help.netflix.com"],
    "bankofamerica": ["www.bankofamerica.com", "secure.bankofamerica.com"],
    "chase": ["www.chase.com", "secure.chase.com"], "wellsfargo": ["www.wellsfargo.com", "connect.secure.wellsfargo.com"],
    "citibank": ["www.citibank.com", "online.citi.com"], "capitalone": ["www.capitalone.com", "verified.capitalone.com"],
    "americanexpress": ["www.americanexpress.com", "global.americanexpress.com"],
    "hsbc": ["www.hsbc.com", "www.hsbc.co.uk", "www.hsbc.co.in"], "dropbox": ["www.dropbox.com"],
    "linkedin": ["www.linkedin.com"], "adobe": ["account.adobe.com", "www.adobe.com", "helpx.adobe.com"],
    "docusign": ["www.docusign.com", "account.docusign.com"], "dhl": ["www.dhl.com"], "fedex": ["www.fedex.com"],
    "usps": ["www.usps.com", "tools.usps.com"], "ups": ["www.ups.com"], "coinbase": ["www.coinbase.com"],
    "binance": ["www.binance.com", "accounts.binance.com"], "metamask": ["metamask.io", "support.metamask.io"],
    "steam": ["store.steampowered.com", "steamcommunity.com"], "spotify": ["accounts.spotify.com", "www.spotify.com"],
    "twitter": ["twitter.com", "x.com"], "yahoo": ["login.yahoo.com", "www.yahoo.com"], "ebay": ["www.ebay.com", "signin.ebay.com"],
    "walmart": ["www.walmart.com"], "zoom": ["zoom.us", "us02web.zoom.us"], "github": ["github.com", "gist.github.com"],
    "sbi": ["www.onlinesbi.sbi", "retail.onlinesbi.com"], "hdfcbank": ["www.hdfcbank.com", "netbanking.hdfcbank.com"],
    "icicibank": ["www.icicibank.com", "infinity.icicibank.com"], "paytm": ["paytm.com", "accounts.paytm.com"],
    "irs": ["www.irs.gov"], "att": ["www.att.com"], "verizon": ["www.verizon.com", "login.verizon.com"],
    "icloud": ["www.icloud.com"], "outlook": ["outlook.live.com", "outlook.office.com"], "office365": ["www.office.com", "portal.office.com"],
}
BRAND_LOGIN_PATHS = ["/login", "/signin", "/account", "/account/login", "/myaccount", "/ap/signin", "/signin/v2/identifier",
                     "/webapps/mpp/home", "/auth/login", "/oauth2/authorize", "/common/oauth2/authorize", "/security",
                     "/account/security", "/verify", "/identity/verify", "/billing", "/settings/account", "/help/password-reset",
                     "/signup", "/ServiceLogin", "/id/login", "/session/new", "/authorize", "/mfa/verify",
                     "/login.php", "/signin.html", "/login/index.html", "/account/login.html", "/en/signin"]
CORP_PATHS = ["/", "/about", "/about-us", "/contact", "/careers", "/careers/open-positions", "/products", "/services",
              "/pricing", "/blog", "/news", "/press", "/investors", "/support", "/faq", "/team", "/privacy", "/terms",
              "/sitemap.xml", "/solutions/enterprise", "/resources/whitepapers", "/events", "/locations"]
SLUG_WORDS = ["how", "to", "guide", "best", "top", "review", "update", "release", "notes", "announces", "new", "launch",
              "tips", "tutorial", "introduction", "getting", "started", "overview", "report", "2024", "2025", "annual",
              "summary", "comparison", "vs", "faq", "policy", "changes", "security", "account", "login", "password",
              "verify", "billing", "support", "wallet", "invoice"]  # lure-ish words appear in legit slugs too
LURE_PATHS = ["/login.php", "/signin.php", "/verify.php", "/secure/login", "/account/verify", "/update/billing",
              "/confirm.html", "/auth/signin.php", "/webscr?cmd=_login-run", "/login/index.php", "/signin/confirm",
              "/account/suspended", "/security/alert", "/wallet/connect", "/invoice/view.php", "/verification/step1",
              "/restore/access", "/unlock/account", "/password/reset.php", "/validate/identity", "/secure/update-info"]
GENERIC_LURE_PATHS = ["/document/view", "/files/invoice", "/shared/doc", "/secure-message", "/payroll/2024", "/voicemail/play",
                      "/shipment/tracking", "/refund/claim", "/prize/claim", "/review/contract", "/onedrive/share", "/sharepoint/doc"]
EVIL_FILES = ["index.php", "login.php", "verify.php", "signin.html", "confirm.php", "update.html", "secure.php", "form.php", "post.php", "next.php"]


# ---------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------
class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)

    # --- primitives
    def c(self, seq):
        return self.r.choice(seq)

    def p(self, prob: float) -> bool:
        return self.r.random() < prob

    def rand_str(self, n, alphabet=string.ascii_lowercase + string.digits):
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def hexs(self, n):
        return self.rand_str(n, "0123456789abcdef")

    def num(self, lo=1, hi=99999):
        return str(self.r.randint(lo, hi))

    # --- shared name generator (used by BOTH classes)
    def company(self) -> str:
        m = self.r.random()
        if m < 0.35:
            return self.c(WORDS) + self.c(WORDS)
        if m < 0.55:
            return self.c(WORDS) + "-" + self.c(WORDS) if self.p(0.4) else self.c(WORDS) + self.c(SYL)
        if m < 0.80:
            return "".join(self.c(SYL) for _ in range(self.r.randint(2, 3)))
        if m < 0.88:
            return self.c(FIRST) + self.c(WORDS)
        if m < 0.94:
            return self.c(WORDS) + self.num(1, 99)
        return self.c(WORDS)

    def dga(self) -> str:
        n = self.r.randint(7, 16)
        m = self.r.random()
        if m < 0.45:
            return self.rand_str(n, string.ascii_lowercase)
        if m < 0.8:
            return self.rand_str(n)
        return self.rand_str(self.r.randint(4, 7), string.ascii_lowercase) + "-" + self.rand_str(self.r.randint(3, 6), string.ascii_lowercase + string.digits)

    def good_tld(self):
        return self.c(GOOD_TLDS) if self.p(0.8) else self.c(CC_TLDS)

    def slug(self, k=None):
        k = k or self.r.randint(2, 6)
        return "-".join(self.c(SLUG_WORDS + [self.c(WORDS)]) for _ in range(k))

    def ip(self, private=False):
        if private:
            return self.c([f"192.168.{self.r.randint(0, 5)}.{self.r.randint(1, 254)}", f"10.0.{self.r.randint(0, 9)}.{self.r.randint(1, 254)}"])
        return ".".join(str(self.r.randint(1, 254)) for _ in range(4))

    def scheme(self, https_p):
        return "https" if self.p(https_p) else "http"

    def utm(self):
        parts = []
        for k, v in [("utm_source", self.c(["newsletter", "twitter", "google", "email"])), ("utm_medium", self.c(["cpc", "social", "email"])),
                     ("ref", self.c(["home", "nav", "footer"])), ("lang", self.c(["en", "de", "fr", "hi"]))]:
            if self.p(0.4):
                parts.append(f"{k}={v}")
        return ("?" + "&".join(parts)) if parts else ""


# ---------------------------------------------------------------------
# LEGITIMATE generators
# ---------------------------------------------------------------------
def legit_corporate(g: Gen):
    host = f"{g.c(SUBS_LEGIT) + '.' if g.p(0.55) else ''}{g.company()}.{g.good_tld()}"
    path = g.c(CORP_PATHS) if g.p(0.7) else "/" + g.c(["products", "services", "blog", "news"]) + "/" + g.slug()
    return f"{g.scheme(0.93)}://{host}{path}{g.utm()}"


def legit_ecommerce(g: Gen):
    host = f"{g.c(['shop', 'store', 'www', 'buy'])}.{g.company()}.{g.good_tld()}"
    path = g.c([f"/products/{g.slug()}-{g.num()}", f"/p/{g.num(100000, 9999999)}", f"/collections/{g.c(WORDS)}/{g.slug(3)}",
                f"/cart", f"/checkout/{g.hexs(8)}", f"/search?q={g.c(WORDS)}+{g.c(WORDS)}&page={g.num(1, 9)}", f"/orders/{g.num(10000, 99999)}/track"])
    return f"{g.scheme(0.95)}://{host}{path}"


def legit_news_blog(g: Gen):
    host = f"{g.c(['www', 'blog', 'news', ''])}{'.' if g.p(0.7) else ''}{g.company()}.{g.good_tld()}".replace("..", ".").lstrip(".")
    y, m = g.c([2021, 2022, 2023, 2024, 2025]), f"{g.r.randint(1, 12):02d}"
    brand_slug = (g.c(BRANDS) + "-" + g.slug(3)) if g.p(0.25) else g.slug()  # legit articles mention brands
    path = g.c([f"/{y}/{m}/{brand_slug}", f"/articles/{brand_slug}", f"/blog/{brand_slug}.html", f"/posts/{g.num(1000, 99999)}-{brand_slug}"])
    return f"{g.scheme(0.9)}://{host}{path}{g.utm()}"


def legit_docs_dev(g: Gen):
    m = g.r.random()
    if m < 0.25:
        return f"https://github.com/{g.c(FIRST)}{g.c(WORDS)}/{g.c(WORDS)}-{g.c(WORDS)}/{g.c(['blob/main/src/app.py', 'issues/' + g.num(1, 4000), 'pull/' + g.num(1, 900), 'tree/main/docs', 'releases/tag/v1.' + g.num(0, 30)])}"
    if m < 0.45:
        return f"https://{g.c(['docs', 'developer', 'help'])}.{g.company()}.{g.c(['io', 'com', 'dev', 'org'])}/{g.c(['en/latest', 'v2', 'guides', 'reference'])}/{g.slug(3)}.html"
    if m < 0.6:
        return f"https://stackoverflow.com/questions/{g.num(100000, 79999999)}/{g.slug(5)}"
    if m < 0.75:
        return f"https://en.wikipedia.org/wiki/{g.c(WORDS).title()}_{g.c(WORDS).title()}"
    if m < 0.9:
        return f"https://{g.c(FIRST)}{g.c(WORDS)}.{g.c(['github.io', 'netlify.app', 'vercel.app', 'pages.dev', 'web.app'])}/{g.c(['', 'about', 'projects/' + g.slug(2), 'blog/' + g.slug(3)])}"
    return f"https://pypi.org/project/{g.c(WORDS)}-{g.c(WORDS)}/{g.num(0, 9)}.{g.num(0, 20)}.{g.num(0, 9)}/"


def legit_edu_gov(g: Gen):
    tld = g.c(["edu", "edu", "ac.uk", "gov", "gov.in", "ac.in", "edu.au", "gov.uk"])
    host = f"{g.c(['www', 'admissions', 'library', 'portal', 'students', 'research', 'login', 'sso', 'secure', 'accounts', 'webmail'])}.{g.c(WORDS)}{g.c(['university', 'college', 'state', 'tech', ''])}.{tld}"
    path = g.c(["/", "/admissions/apply", "/library/catalog?q=" + g.c(WORDS), "/students/login", "/research/papers/" + g.num(100, 9999) + ".pdf", "/forms/" + g.slug(2) + ".pdf", "/news/" + g.slug(4), "/courses/" + g.c(['cs', 'math', 'bio']) + g.num(100, 499)])
    return f"{g.scheme(0.9)}://{host}{path}"


def legit_brand_official(g: Gen):
    """HARD NEGATIVE: real brands on official hosts with login-ish paths and redirects."""
    brand = g.c(list(OFFICIAL_HOSTS))
    host = g.c(OFFICIAL_HOSTS[brand])
    path = g.c(BRAND_LOGIN_PATHS)
    q = ""
    m = g.r.random()
    if m < 0.35:
        tgt = g.c([f"https://{host}/home", f"https://{host}/browse", f"https://{host.split('.', 1)[-1] if host.count('.') > 1 else host}/dashboard"])
        q = f"?{g.c(['continue', 'next', 'returnUrl', 'redirect_uri', 'nextpage', 'service'])}={quote(tgt, safe='')}"
    elif m < 0.5:
        q = f"?client_id={g.hexs(16)}&response_type=code&scope=openid+email&state={g.hexs(12)}"
    elif m < 0.6:
        q = f"?locale={g.c(['en_US', 'en_GB', 'de_DE', 'hi_IN'])}"
    return f"{g.scheme(0.985)}://{host}{path}{q}"


def legit_brand_oauth_crossdomain(g: Gen):
    """Real OAuth: official login host redirecting to a third-party app (cross-domain redirect but legit)."""
    brand = g.c(["google", "microsoft", "github", "facebook", "linkedin", "twitter", "apple", "spotify", "dropbox"])
    host = g.c(OFFICIAL_HOSTS[brand])
    app = f"https://{g.c(['app', 'www', 'auth'])}.{g.company()}.{g.c(['com', 'io', 'app'])}/{g.c(['callback', 'oauth/callback', 'auth/complete'])}"
    return f"https://{host}{g.c(['/oauth2/authorize', '/login/oauth/authorize', '/o/oauth2/v2/auth', '/authorize'])}?client_id={g.hexs(20)}&redirect_uri={quote(app, safe='')}&response_type=code&scope=email"


def legit_saas_login(g: Gen):
    """HARD NEGATIVE: ordinary companies' own login/billing/support pages, on bare, www and sub hosts."""
    co = f"{g.company()}.{g.good_tld()}"
    sub = g.c(["app", "accounts", "login", "auth", "id", "my", "portal", "secure", "billing", "sso", "admin"])
    path = g.c(["/login", "/login", "/signin", "/signin", "/sign-in", "/log-in", "/account/login", "/login.php", "/signin.html", "/login.html",
                "/account/billing", "/account/security", "/verify-email?token=" + g.hexs(32), "/password/reset", "/invoices/" + g.num(1000, 99999),
                "/settings/profile", "/sso/saml", "/auth/callback?code=" + g.hexs(20), "/users/sign_in", "/confirm?email=" + g.c(FIRST) + "%40" + g.company() + ".com",
                "/signin?next=" + quote("/dashboard", safe=""), "/login?redirect=" + quote("https://" + co + "/home", safe="")])
    m = g.r.random()
    host = co if m < 0.3 else (f"www.{co}" if m < 0.55 else f"{sub}.{co}")
    return f"{g.scheme(0.97)}://{host}{path}"


def legit_php_app(g: Gen):
    """HARD NEGATIVE: forums/CMS/older sites whose normal login/admin pages are scripts (.php/.aspx)."""
    host = f"{g.c(['www.', '', 'forum.', 'community.', 'members.'])}{g.company()}.{g.good_tld()}"
    path = g.c(["/login.php", "/wp-login.php", "/member.php?action=login", "/index.php?route=account/login", "/user/login", "/accounts/login/",
                "/customer/account/login/", "/admin/login.php", "/ucp.php?mode=login", "/login.aspx", "/Account/Login.aspx?ReturnUrl=%2fhome",
                "/signin.html", "/my-account/", "/forum/viewtopic.php?t=" + g.num(1, 99999), "/index.php?page=" + g.c(WORDS), "/register.php", "/verify.php?id=" + g.num(1, 9999)])
    return f"{g.scheme(0.9)}://{host}{path}"


def legit_brand_mention_third_party(g: Gen):
    """HARD NEGATIVE: brand names (even with 'login') appearing on THIRD-PARTY legit sites --
    review/status/forum/wiki/search pages. A brand in the URL is not proof of impersonation."""
    brand = g.c(BRANDS)
    cap = brand.title()
    m = g.r.random()
    if m < 0.15:
        return f"https://www.trustpilot.com/review/{brand}.com"
    if m < 0.3:
        return f"https://downdetector.com/status/{brand}/"
    if m < 0.45:
        return f"https://en.wikipedia.org/wiki/{cap}"
    if m < 0.6:
        return f"https://www.google.com/search?q={brand}+{g.c(['login', 'sign+in', 'customer+service', 'password+reset', 'verify+account'])}&hl=en"
    if m < 0.72:
        return f"https://www.reddit.com/r/{brand}/comments/{g.rand_str(6)}/{brand}_{g.c(['login', 'account', 'verify', 'security'])}_{g.c(['issue', 'problem', 'help'])}/"
    if m < 0.84:
        return f"https://medium.com/@{g.c(FIRST)}{g.num(1, 99)}/{g.slug(3)}-{brand}-{g.slug(2)}-{g.hexs(12)}"
    if m < 0.93:
        return f"https://support.{g.company()}.{g.c(['com', 'io', 'org'])}/hc/en-us/articles/{g.num(100000, 999999)}-how-to-connect-your-{brand}-account"
    return f"https://www.youtube.com/results?search_query={brand}+{g.c(['login', 'tutorial', 'security'])}"


def legit_search_social(g: Gen):
    m = g.r.random()
    if m < 0.25:
        return f"https://www.google.com/search?q={g.c(WORDS)}+{g.c(WORDS)}&hl=en&source=hp&ei={g.rand_str(20, string.ascii_letters + string.digits)}"
    if m < 0.45:
        return f"https://www.youtube.com/watch?v={g.rand_str(11, string.ascii_letters + string.digits + '-_')}"
    if m < 0.6:
        return f"https://twitter.com/{g.c(FIRST)}{g.num(1, 99)}/status/{g.num(10**17, 10**18)}"
    if m < 0.75:
        return f"https://www.reddit.com/r/{g.c(WORDS)}/comments/{g.rand_str(6)}/{g.slug(4).replace('-', '_')}/"
    if m < 0.9:
        return f"https://www.linkedin.com/in/{g.c(FIRST)}-{g.c(WORDS)}-{g.hexs(8)}"
    return f"https://www.amazon.com/{g.slug(5)}/dp/B0{g.rand_str(8, string.ascii_uppercase + string.digits)}/ref=sr_1_{g.num(1, 9)}?keywords={g.c(WORDS)}&qid={g.num(10**9, 10**10)}"


def legit_cdn_api(g: Gen):
    m = g.r.random()
    if m < 0.5:
        return f"https://cdn.{g.company()}.{g.c(['com', 'net', 'io'])}/assets/{g.c(['app', 'main', 'vendor'])}.{g.hexs(g.c([8, 16, 32, 40]))}.{g.c(['js', 'css', 'png', 'woff2'])}"
    if m < 0.8:
        return f"https://api.{g.company()}.{g.c(['com', 'io', 'dev'])}/v{g.num(1, 3)}/{g.c(['users', 'items', 'orders', 'events'])}/{g.c([g.num(1, 99999), g.hexs(24), str(g.r.getrandbits(64))])}"
    return f"https://{g.company()}.{g.c(['s3.amazonaws.com', 'blob.core.windows.net', 'storage.googleapis.com'])}/{g.c(['uploads', 'files', 'media'])}/{g.hexs(g.c([24, 32]))}/{g.c(['report', 'photo', 'doc'])}.{g.c(['pdf', 'jpg', 'png'])}"


def legit_odd_domain(g: Gen):
    """HARD NEGATIVE: legit sites with hyphens, digits, cheap TLDs, plain http, odd ports, deep subdomains."""
    m = g.r.random()
    if m < 0.3:
        host = f"{g.company()}-{g.c(WORDS)}.{g.c(LEGIT_ODD_TLDS + GOOD_TLDS)}"
        return f"{g.scheme(0.8)}://{host}{g.c(CORP_PATHS)}"
    if m < 0.5:
        host = f"{g.c(WORDS)}{g.num(1, 999)}.{g.c(LEGIT_ODD_TLDS)}"
        return f"{g.scheme(0.75)}://{host}/{g.c(['', 'shop', 'about', 'menu', 'gallery'])}"
    if m < 0.65:
        return f"{g.scheme(0.4)}://{g.c(['staging', 'dev', 'test', 'intranet'])}.{g.company()}.{g.c(GOOD_TLDS)}:{g.c([8080, 8443, 3000, 8000])}/{g.c(['', 'admin', 'login', 'dashboard'])}"
    if m < 0.78:
        return f"https://{g.c(['a', 'eu', 'us-east', 'mail', 'vpn'])}.{g.c(['corp', 'hq', 'internal'])}.{g.company()}.{g.good_tld()}/{g.c(['', 'owa', 'login', 'remote'])}"
    if m < 0.9:
        return f"http://{g.ip(private=True)}{g.c(['', ':8080', ':80'])}/{g.c(['', 'admin', 'index.html', 'login.html', 'status'])}"
    return f"https://{g.company()}.{g.c(['co.uk', 'com.au', 'co.in', 'com.br', 'de'])}/{g.c(['', 'kontakt', 'about', 'products/' + g.slug(2)])}"


def legit_hosted(g: Gen):
    """Legit personal/project sites on free hosting platforms, names without brand/lure abuse."""
    plat = g.c(["netlify.app", "vercel.app", "github.io", "web.app", "pages.dev", "herokuapp.com", "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "glitch.me", "firebaseapp.com", "webcindario.com", "wasmer.app"])
    sub = g.c(FIRST) + "-" + g.c(WORDS) if g.p(0.5) else g.company()
    path = g.c(["", "/", "/about", "/portfolio", "/blog/" + g.slug(3), "/projects", "/contact", "/index.html"])
    if plat == "wixsite.com":
        return f"https://{g.c(FIRST)}{g.c(WORDS)}.wixsite.com/{g.c(WORDS)}-{g.c(WORDS)}"
    return f"https://{sub}.{plat}{path}"


def legit_shortener(g: Gen):
    return f"{g.scheme(0.9)}://{g.c(['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 'rebrand.ly', 'lnkd.in', 'qrco.de', 'l.ead.me', 'linktr.ee', 't.ly', 'qr-codes.io'])}/{g.rand_str(g.r.randint(5, 8), string.ascii_letters + string.digits)}"


def legit_international(g: Gen):
    host = f"{g.c(['www', 'shop', 'm', ''])}{'.' if g.p(0.7) else ''}{g.company()}.{g.c(CC_TLDS)}".replace("..", ".").lstrip(".")
    return f"{g.scheme(0.93)}://{host}/{g.c(['de/produkte', 'fr/contact', 'es/tienda', 'in/hi/home', 'jp/news', 'en/about', 'br/produtos'])}/{g.slug(2)}"


# ---------------------------------------------------------------------
# PHISHING generators
# ---------------------------------------------------------------------
def _evil_domain(g: Gen):
    if g.p(0.55):
        return f"{g.company() if g.p(0.5) else g.dga()}.{g.c(CHEAP)}"
    return f"{g.company() if g.p(0.6) else g.dga()}.{g.good_tld()}"


def _lure_name(g: Gen, brand=None):
    toks = [g.c(LURE) for _ in range(g.r.randint(1, 3))]
    if brand:
        toks.insert(g.r.randint(0, len(toks)), brand)
    return "-".join(toks)


def phish_subdomain_brand(g: Gen):
    brand = g.c(BRANDS)
    evil = _evil_domain(g)
    m = g.r.random()
    if m < 0.35:
        host = f"{brand}.{g.c(LURE)}.{evil}"
    elif m < 0.6:
        host = f"{g.c(LURE)}.{brand}.com.{evil}"
    elif m < 0.8:
        host = f"{brand}-{g.c(LURE)}.{evil}"
    else:
        host = f"{g.c(['www', 'login', 'secure', 'accounts'])}.{brand}.{g.c(LURE)}-{g.c(LURE)}.{g.c(CHEAP + ['com', 'net', 'info'])}"
    path = g.c(["/", g.c(LURE_PATHS), "/" + g.c(LURE) + "/", "/" + g.hexs(8) + "/" + g.c(EVIL_FILES)])
    return f"{g.scheme(0.6)}://{host}{path}"


def phish_typosquat(g: Gen):
    brand = g.c([b for b in BRANDS if len(b) >= 5])
    m = g.r.random()
    if m < 0.35:  # leetspeak (optionally with a lure word attached, e.g. faceb00k-security)
        sub = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5"}
        cand = [i for i, ch in enumerate(brand) if ch in sub]
        s = list(brand)
        for i in g.r.sample(cand, k=min(len(cand), g.r.randint(1, 2))) if cand else []:
            s[i] = sub[s[i]]
        name = "".join(s)
        if name == brand:
            name = brand + "l"
        if g.p(0.4):
            name = f"{name}-{g.c(LURE)}" if g.p(0.6) else f"{g.c(LURE)}-{name}"
    elif m < 0.6:  # drop/dup/swap
        i = g.r.randint(1, len(brand) - 2)
        op = g.c(["drop", "dup", "swap", "sub"])
        s = list(brand)
        if op == "drop":
            del s[i]
        elif op == "dup":
            s.insert(i, s[i])
        elif op == "swap":
            s[i], s[i + 1 if i + 1 < len(s) else i - 1] = s[i + 1 if i + 1 < len(s) else i - 1], s[i]
        else:
            s[i] = g.c(string.ascii_lowercase)
        name = "".join(s)
        if name == brand:
            name = brand[:-1]
    elif m < 0.8:  # rn -> m, vv -> w, etc.
        name = brand.replace("m", "rn", 1) if "m" in brand else brand.replace("w", "vv", 1) if "w" in brand else brand + "-" + g.c(LURE)
    else:
        name = f"{brand}{g.c(['-', ''])}{g.c(['online', 'secure', 'help', 'login', 'verify', 'support', 'app'])}"
    tld = g.c(["com", "net", "co", "info", "org", "support"] + CHEAP) if g.p(0.85) else g.c(CC_TLDS)
    path = g.c(["/", "/", g.c(LURE_PATHS), "/" + g.c(LURE), "/login"])
    return f"{g.scheme(0.7)}://{g.c(['www.', '', ''])}{name}.{tld}{path}"


def phish_brand_exact_wrong_tld(g: Gen):
    brand = g.c(BRANDS)
    tld = g.c(CHEAP + ["net", "info", "biz", "co", "us", "org", "online"])
    if g.p(0.15):
        tld = g.c(["com.co", "co.in", "com.ng", "com.pk"])  # brand on a different country suffix it doesn't own
        if registrable_domain(f"{brand}.{tld}") in BRAND_DOMAINS[brand]:
            tld = "net"
    return f"{g.scheme(0.7)}://{g.c(['www.', '', 'secure.', 'login.'])}{brand}.{tld}{g.c(['/', '/' + g.c(LURE), g.c(LURE_PATHS)])}"


def phish_keyword_hyphen(g: Gen):
    brand = g.c(BRANDS) if g.p(0.55) else None
    name = _lure_name(g, brand)
    tld = g.c(CHEAP + ["com", "net", "info", "org", "online", "co"])
    path = g.c(["/", "/", g.c(LURE_PATHS), "/" + g.c(EVIL_FILES)])
    return f"{g.scheme(0.7)}://{name}.{tld}{path}"


def phish_ip_host(g: Gen):
    brand = g.c(BRANDS)
    host = g.ip()
    if g.p(0.3):
        host += ":" + g.c(["8080", "8000", "8443", "2083", "81", "8888"])
    path = g.c([f"/{brand}/login.php", f"/{brand}/signin/", f"/{g.c(LURE)}/{g.c(EVIL_FILES)}", f"/~{g.rand_str(6)}/{brand}/index.php", f"/{g.hexs(10)}/{g.c(EVIL_FILES)}",
                f"/{g.c(['bank', 'secure', 'account'])}/{g.c(LURE)}.html", "/"])
    return f"{g.scheme(0.2)}://{host}{path}"


def phish_shortener(g: Gen):
    return f"{g.scheme(0.9)}://{g.c(sorted(SHORTENERS))}/{g.rand_str(g.r.randint(5, 8), string.ascii_letters + string.digits)}"


def phish_free_hosting(g: Gen):
    brand = g.c(BRANDS)
    plat = g.c(["weebly.com", "web.app", "firebaseapp.com", "wixsite.com", "blogspot.com", "000webhostapp.com", "netlify.app", "pages.dev", "glitch.me", "herokuapp.com", "github.io", "godaddysites.com", "azurewebsites.net", "workers.dev", "webcindario.com", "wasmer.app", "wixstudio.com"])
    m = g.r.random()
    if m < 0.45:
        sub = _lure_name(g, brand)
    elif m < 0.75:
        sub = g.dga()
    else:
        sub = g.company()
    path = g.c(["", "/", f"/{brand}/login.html", f"/{g.c(LURE)}/", f"/{g.c(EVIL_FILES)}", f"/{brand}", "/index.html", f"/{g.hexs(8)}"])
    if plat == "wixsite.com":
        return f"https://{g.company()}.wixsite.com/{g.c(['', brand + '-' + g.c(LURE), g.c(LURE)])}"
    return f"https://{sub}.{plat}{path}"


def phish_compromised_path(g: Gen):
    """Legit-looking domain (shared name generator) with a lure buried deep in the path."""
    brand = g.c(BRANDS)
    host = f"{g.c(['www.', '', ''])}{g.company()}.{g.good_tld()}"
    stem = g.c(["/wp-content/plugins/", "/wp-includes/", "/images/", "/includes/", "/admin/", "/cgi-bin/", "/.well-known/", f"/~{g.rand_str(5)}/", "/assets/", "/uploads/", "/tmp/"])
    path = f"{stem}{g.c([g.rand_str(6), g.hexs(8), g.c(WORDS)])}/{g.c([brand, g.c(LURE), brand + '-' + g.c(LURE)])}/{g.c(EVIL_FILES)}"
    return f"{g.scheme(0.65)}://{host}{path}"


def phish_clean_domain_lure(g: Gen):
    """HARD POSITIVE: nothing wrong with the host; lure only in path/query.
    Mixed on purpose: some are plain kit paths (/login.php) that look just
    like ordinary legit login pages, most carry extra attack-style structure."""
    host = f"{g.c(['www.', '', 'secure.', 'login.', 'mail.'])}{g.company()}.{g.good_tld()}"
    m = g.r.random()
    if m < 0.22:
        path = g.c(["/login.php", "/signin.html", "/verify.php", "/confirm.html", "/secure/login", "/account/verify"])
    elif m < 0.5:
        path = g.c(GENERIC_LURE_PATHS) + g.c(["", ".php", ".html", f"?id={g.hexs(10)}", f"?ref={g.rand_str(12)}"])
    elif m < 0.8:
        path = g.c(LURE_PATHS) + g.c([f"?token={g.hexs(24)}&email={g.c(FIRST)}%40{g.company()}.com", f"?id={g.hexs(10)}", f"?session={g.hexs(32)}&user={g.c(FIRST)}", f"&u={g.num(1, 99999)}"])
    else:
        path = f"/{g.c(LURE)}-{g.c(LURE)}/{g.c(EVIL_FILES)}"
    return f"{g.scheme(0.8)}://{host}{path}"


def phish_dga_cheap(g: Gen):
    host = f"{g.dga()}.{g.c(CHEAP)}"
    path = g.c(["/", "/", f"/{g.c(EVIL_FILES)}", f"/?id={g.num(1, 99999)}", f"/{g.rand_str(6)}/{g.c(EVIL_FILES)}", f"/{g.c(LURE)}", f"/?{g.rand_str(8)}"])
    return f"{g.scheme(0.55)}://{host}{path}"


def phish_punycode(g: Gen):
    brand = g.c([b for b in BRANDS if len(b) >= 5])
    puny = f"xn--{brand[:-1]}-{g.rand_str(3, string.ascii_lowercase + string.digits)}"
    return f"https://{puny}.{g.c(['com', 'net', 'org', 'co'] + CHEAP[:6])}{g.c(['/', g.c(LURE_PATHS)])}"


def phish_at_trick(g: Gen):
    brand = g.c(BRANDS)
    shown = g.c([f"www.{brand}.com", f"{brand}.com", f"secure.{brand}.com", f"accounts.{brand}.com"])
    return f"{g.scheme(0.6)}://{shown}@{_evil_domain(g)}{g.c(['/', g.c(LURE_PATHS), '/' + g.c(EVIL_FILES)])}"


def phish_malformed_query(g: Gen):
    brand = g.c(list(OFFICIAL_HOSTS))
    host = g.c(OFFICIAL_HOSTS[brand]) if g.p(0.5) else f"{g.c(['www.', ''])}{brand}-{g.c(LURE)}.{g.c(CHEAP + ['com', 'net'])}"
    junk = g.c(["scM?ogin?nextpage=", "login?ogin?next=", "signin?x?redirect=", "ac?count?continue=", "verify??u="])
    tgt = quote(f"https://{host.split('@')[-1]}/{g.c(['browse', 'home', 'dashboard'])}", safe="")
    return f"https://{host}/{junk}{tgt}"


def phish_open_redirect(g: Gen):
    evil = _evil_domain(g)
    brand = g.c(BRANDS)
    base = g.c([f"https://{g.company()}.{g.good_tld()}/redirect", f"https://{g.company()}.{g.good_tld()}/out", f"https://{g.company()}.{g.good_tld()}/go", f"https://{g.company()}.{g.good_tld()}/click", f"https://{g.company()}.{g.good_tld()}/r"])
    param = g.c(["url", "u", "target", "link", "dest", "redirect", "goto"])
    tgt = f"{g.scheme(0.7)}://{evil}/{g.c([brand + '/login', g.c(LURE), g.c(EVIL_FILES)])}"
    enc = quote(tgt, safe="") if g.p(0.7) else tgt
    return f"{base}?{param}={enc}{g.c(['', '&token=' + g.hexs(16), '&uid=' + g.num()])}"


def phish_deep_subdomain(g: Gen):
    parts = [g.c(LURE) for _ in range(g.r.randint(2, 4))]
    host = ".".join(parts) + "." + _evil_domain(g)
    return f"{g.scheme(0.65)}://{host}{g.c(['/', g.c(LURE_PATHS)])}"


def phish_fake_download(g: Gen):
    host = f"{g.c(['', 'download.', 'get.', 'files.'])}{g.company() if g.p(0.5) else g.dga()}.{g.c(CHEAP + ['com', 'net', 'info'])}"
    brand = g.c(["adobe", "zoom", "microsoft", "docusign", "dhl", "fedex", "usps"])
    return f"{g.scheme(0.5)}://{host}/{g.c(['downloads', 'files', 'update', brand])}/{brand}_{g.c(['setup', 'update', 'invoice', 'document', 'installer'])}.{g.c(['exe', 'zip', 'apk', 'scr', 'rar'])}"


def phish_homoglyph_path_brand(g: Gen):
    """Brand only appears in the path of an unrelated cheap-TLD domain."""
    brand = g.c(BRANDS)
    host = f"{g.company()}.{g.c(CHEAP)}"
    return f"{g.scheme(0.6)}://{host}/{brand}/{g.c(LURE)}{g.c(['', '/', '.php', '.html'])}"


# (generator, weight, category)
LEGIT_SPECS = [
    (legit_corporate, 13, "corporate"), (legit_ecommerce, 9, "ecommerce"), (legit_news_blog, 10, "news_blog"),
    (legit_docs_dev, 9, "docs_dev"), (legit_edu_gov, 6, "edu_gov"), (legit_brand_official, 12, "brand_official_login"),
    (legit_brand_oauth_crossdomain, 3, "oauth_crossdomain"), (legit_saas_login, 11, "saas_login"),
    (legit_search_social, 7, "search_social"), (legit_cdn_api, 5, "cdn_api"), (legit_odd_domain, 7, "odd_domain"),
    (legit_hosted, 4, "free_hosting_legit"), (legit_shortener, 3, "shortener_legit"), (legit_php_app, 4, "php_app_login"), (legit_brand_mention_third_party, 5, "brand_mention_third_party"), (legit_international, 4, "international"),
]
PHISH_SPECS = [
    (phish_subdomain_brand, 13, "brand_subdomain"), (phish_typosquat, 12, "typosquat"), (phish_brand_exact_wrong_tld, 6, "brand_wrong_tld"),
    (phish_keyword_hyphen, 11, "keyword_hyphen"), (phish_ip_host, 6, "ip_host"), (phish_shortener, 3, "shortener"),
    (phish_free_hosting, 9, "free_hosting"), (phish_compromised_path, 10, "compromised_path"),
    (phish_clean_domain_lure, 9, "clean_domain_lure"), (phish_dga_cheap, 6, "dga_cheap_tld"), (phish_punycode, 1.5, "punycode"),
    (phish_at_trick, 2, "at_trick"), (phish_malformed_query, 2.5, "malformed_query"), (phish_open_redirect, 3, "open_redirect"),
    (phish_deep_subdomain, 3, "deep_subdomain"), (phish_fake_download, 2, "fake_download"), (phish_homoglyph_path_brand, 3, "brand_in_path"),
]


def _domain_group(url: str) -> str:
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    for suffix in FREE_HOSTING:
        if host == suffix or host.endswith("." + suffix):
            return host
    return registrable_domain(host)


def generate(n_total: int = 80000, seed: int = 42, val_frac: float = 0.15, test_frac: float = 0.15) -> pd.DataFrame:
    g = Gen(seed)
    rows, seen = [], set()

    def fill(specs, label, n):
        gens, weights, cats = zip(*[(s[0], s[1], s[2]) for s in specs])
        made, guard = 0, 0
        while made < n and guard < n * 40:
            guard += 1
            i = g.r.choices(range(len(gens)), weights=weights)[0]
            url = gens[i](g)
            if url in seen:
                continue
            seen.add(url)
            rows.append({"url": url, "label": label, "category": cats[i]})
            made += 1

    fill(LEGIT_SPECS, 0, n_total // 2)
    fill(PHISH_SPECS, 1, n_total - n_total // 2)
    df = pd.DataFrame(rows)

    # domain-disjoint split: whole registrable domains (or full hosts on
    # shared-hosting platforms) go to exactly one split.
    df["group"] = df["url"].map(_domain_group)
    groups = sorted(df["group"].unique())
    g.r.shuffle(groups)
    n_g = len(groups)
    cut_test, cut_val = int(n_g * test_frac), int(n_g * (test_frac + val_frac))
    split_of = {}
    for i, grp in enumerate(groups):
        split_of[grp] = "test" if i < cut_test else ("val" if i < cut_val else "train")
    df["split"] = df["group"].map(split_of)
    df = df.drop(columns=["group"]).sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


def main():
    ap = argparse.ArgumentParser(description="Generate the synthetic PhishScan URL dataset")
    ap.add_argument("--n", type=int, default=80000, help="total URLs (half phishing / half legitimate)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=OUT_FILE)
    args = ap.parse_args()

    df = generate(args.n, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} synthetic URLs -> {args.out}")
    print(df.groupby(["split", "label"]).size().unstack(fill_value=0))
    print(df.groupby(["label", "category"]).size())


if __name__ == "__main__":
    main()
