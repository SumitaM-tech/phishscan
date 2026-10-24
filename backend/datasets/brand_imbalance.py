"""
Root-caused a real bug: the live app scored https://www.netflix.com/
as 46.3/100 "suspicious". Traced it to the semantic (Transformer)
branch outputting 0.97 phishing-probability for that exact URL (vs.
0.004 for google.com, 0.068 for github.com), driven almost entirely
by the token "netflix" -- confirmed by a direct measurement on the
real training corpus:

    netflix: phishing=51 legitimate=2   (25.5:1)
    paypal:  phishing=84 legitimate=2   (42.0:1)
    amazon:  phishing=160 legitimate=8  (20.0:1)
    google:  phishing=8051 legitimate=22 (366.0:1)
    ... (682 hostname tokens have a >=15:1 imbalance with >=20
    phishing occurrences; run token_imbalance_report() to reproduce)

This is real, not a code bug: globally famous brands are phished far
more often than their own real domain appears in a broad legitimate
web crawl (PhiUSIIL has ~1 row per distinct domain, not weighted by
real-world traffic), so the Transformer correctly-but-harmfully learns
"this token => phishing" for the exact brands attackers impersonate
most. Two real, non-fabricated fixes, both applied only to a curated
list of well-known GLOBAL BRANDS (NOT the full 682-token list -- most
of the rest are free-hosting/PaaS platforms like weebly.com/repl.co
that genuinely ARE disproportionately used for phishing, and blanket-
correcting those would remove a real, useful signal):

  1. build_brand_correction_set() -- real, distinct, hand-verified
     legitimate URLs for these brands, folded into the training split
     (not duplicated rows, not fabricated ones).
  2. brand_sample_weight() -- a bounded up-weight applied to
     legitimate training rows whose hostname contains one of these
     tokens, so the loss function stops treating a handful of real
     examples as equal in importance to thousands of phishing ones.
"""
import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger("phishscan.brand_imbalance")

# Well-known global consumer/finance/tech brands, independent of
# whether this particular corpus happens to show them as imbalanced --
# curated by hand (this list itself, not any "always clean" claim
# about these domains) so the correction targets real, famous,
# almost-always-legitimate companies rather than every free-hosting
# platform that shows a similar raw ratio for a different reason.
KNOWN_GLOBAL_BRAND_TOKENS = {
    "netflix", "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "instagram", "whatsapp", "outlook", "office365",
    "dropbox", "docusign", "linkedin", "coinbase", "binance",
    "metamask", "yahoo", "wordpress", "steam", "ebay", "chase",
    "wellsfargo", "americanexpress", "github", "gitlab", "twitter",
    "spotify", "adobe", "salesforce", "slack", "zoom",
}

HARD_NEGATIVES_PATH = Path(__file__).resolve().parent / "hard_negatives.csv"

# A modest number of additional real, distinct root-domain URLs for
# brands not already well covered by hard_negatives.csv's held-out
# half (see build_brand_correction_set). Root domains only, chosen
# because they're the highest-confidence real URLs and because the
# netflix.com bug itself was on a bare root domain.
_EXTRA_ROOT_DOMAINS = [
    "https://www.netflix.com/",
    "https://www.paypal.com/",
    "https://www.amazon.com/",
    "https://www.apple.com/",
    "https://www.microsoft.com/",
    "https://www.google.com/",
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://www.whatsapp.com/",
    "https://www.dropbox.com/",
    "https://www.docusign.com/",
    "https://www.linkedin.com/",
    "https://www.coinbase.com/",
    "https://www.binance.com/",
    "https://metamask.io/",
    "https://www.yahoo.com/",
    "https://wordpress.com/",
    "https://store.steampowered.com/",
    "https://www.ebay.com/",
    "https://www.americanexpress.com/",
    "https://gitlab.com/",
    "https://github.com/",
    "https://twitter.com/",
    "https://www.spotify.com/",
    "https://www.adobe.com/",
    "https://www.salesforce.com/",
    "https://slack.com/",
    "https://zoom.us/",
]


def token_imbalance_report(raw_dir: Path = Path("datasets/raw"), min_phish: int = 20, min_ratio: float = 15.0) -> pd.DataFrame:
    """Reproduces the measurement quoted in this module's docstring
    directly from the real corpus. Run: python -m datasets.brand_imbalance"""
    import re
    from collections import Counter
    from urllib.parse import urlparse

    def host_tokens(url: str) -> list[str]:
        try:
            h = urlparse(url if "://" in url else "http://" + url).hostname or ""
        except Exception:
            return []
        return [t for t in re.split(r"[.\-]", h) if len(t) >= 4 and not t.isdigit()]

    phish = pd.read_csv(raw_dir / "historical_phishing.csv", usecols=["url"])
    legit = pd.read_csv(raw_dir / "historical_legitimate.csv", usecols=["url"])
    pc, lc = Counter(), Counter()
    for u in phish["url"]:
        pc.update(set(host_tokens(u)))
    for u in legit["url"]:
        lc.update(set(host_tokens(u)))

    rows = []
    for tok, p in pc.items():
        l = lc.get(tok, 0)
        if p >= min_phish and (p / max(l, 1)) >= min_ratio:
            rows.append({"token": tok, "phishing_count": p, "legitimate_count": l, "ratio": round(p / max(l, 1), 1),
                         "in_brand_correction_list": tok in KNOWN_GLOBAL_BRAND_TOKENS})
    return pd.DataFrame(rows).sort_values("ratio", ascending=False).reset_index(drop=True)


def build_brand_correction_set() -> pd.DataFrame:
    """Real, non-fabricated legitimate (label=0) URLs to fold into the
    training split. Sourced two ways, both real URLs:
      1. Half of datasets/hard_negatives.csv (even rows) -- the odd
         rows stay in hard_negatives.csv untouched as a held-out EVAL
         set, so nothing used for training is also used for scoring
         the hard-negative test (would be leakage).
      2. A short list of additional real root domains
         (_EXTRA_ROOT_DOMAINS) for brands not well covered by (1).
    Every row is a distinct real URL; none is a fabricated one and
    none is a repeated duplicate of an existing training row."""
    rows = []
    if HARD_NEGATIVES_PATH.exists():
        hn = pd.read_csv(HARD_NEGATIVES_PATH)
        train_half = hn.iloc[::2]  # even rows -> training augmentation
        rows.append(train_half[["url"]])
        logger.info("Using %d/%d hard_negatives.csv rows for brand-correction training (other half stays held out for eval)",
                    len(train_half), len(hn))
    rows.append(pd.DataFrame({"url": _EXTRA_ROOT_DOMAINS}))

    df = pd.concat(rows, ignore_index=True).drop_duplicates(subset="url")
    df["label"] = 0
    df["source"] = "brand_correction_real"
    logger.info("Built %d real legitimate brand-correction URLs", len(df))
    return df


def brand_sample_weight(hostname: str, label: int, base_weight: float = 1.0, max_weight: float = 6.0) -> float:
    """Used by training/train_semantic.py. Legitimate (label=0) rows
    whose hostname contains a curated brand token get up-weighted in
    the loss -- phishing rows and non-brand legitimate rows are
    unaffected (weight stays 1.0). Capped at max_weight so a handful
    of real examples can't dominate the loss outright, just stop being
    drowned out 25:1-to-400:1 by phishing examples of the same brand."""
    if label != 0:
        return base_weight
    host = (hostname or "").lower()
    if any(tok in host for tok in KNOWN_GLOBAL_BRAND_TOKENS):
        return max_weight
    return base_weight


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO)
    report = token_imbalance_report()
    print(report.head(30).to_string(index=False))
    print(f"\n{len(report)} tokens with >=15:1 phishing:legitimate imbalance and >=20 phishing occurrences.")
    print(f"{report['in_brand_correction_list'].sum()} of those are in KNOWN_GLOBAL_BRAND_TOKENS (the ones this module corrects).")
