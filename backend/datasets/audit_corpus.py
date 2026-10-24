"""
Phase 1 audit: real, measured statistics on the historical training
corpus (PhishTank historical CSV + PhiUSIIL), computed directly from
datasets/historical_sources/. No estimates, no synthetic numbers --
every figure below is `.groupby()`/`.value_counts()` on the actual
files. Run: python -m datasets.audit_corpus
Writes datasets/processed/audit_report.json (machine-readable) and
prints a human-readable summary.
"""
import json
import logging
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from datasets.loaders import load_historical_corpus
from app.services.url_service import normalize_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.audit")

OUT = Path(__file__).resolve().parent / "processed" / "audit_report.json"


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without a public-suffix-list network fetch
    (no live network in this environment). Handles the common
    two-label public suffixes (co.uk, com.br, ...); falls back to
    last-two-labels otherwise. Good enough for grouping/leakage
    analysis; NOT a substitute for a real PSL in production (see
    README limitations)."""
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_label_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "co.jp", "com.br",
        "com.au", "co.za", "com.cn", "com.mx", "com.tr", "co.id", "co.kr",
    }
    last_two = ".".join(labels[-2:])
    if last_two in two_label_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def audit():
    raw = load_historical_corpus()
    report = {"total_raw_rows": int(len(raw))}
    report["source_distribution"] = raw["source"].value_counts().to_dict()

    df = raw.drop_duplicates(subset="url").copy()
    report["duplicate_raw_urls_removed"] = int(len(raw) - len(df))

    df["normalized"] = df["url"].apply(lambda u: normalize_url(str(u)))
    n_unnormalizable = int(df["normalized"].isna().sum())
    df = df[df["normalized"].notna()]
    report["unnormalizable_urls_dropped"] = n_unnormalizable

    n_before_norm_dedup = len(df)
    df = df.drop_duplicates(subset="normalized", keep="first")
    report["duplicate_normalized_urls_removed"] = int(n_before_norm_dedup - len(df))
    report["final_clean_rows"] = int(len(df))

    df["host"] = df["normalized"].apply(lambda u: urlparse(u).hostname or "")
    df["registrable_domain"] = df["host"].apply(registrable_domain)
    df["parsed"] = df["normalized"].apply(urlparse)
    df["has_path"] = df["parsed"].apply(lambda p: p.path not in ("", "/"))
    df["has_query"] = df["parsed"].apply(lambda p: bool(p.query))
    df["uses_www"] = df["host"].str.startswith("www.")
    df["tld"] = df["registrable_domain"].apply(lambda d: d.rsplit(".", 1)[-1] if "." in d else d)
    df["host_len"] = df["host"].str.len()

    report["class_distribution"] = {
        "phishing": int((df.label == 1).sum()),
        "legitimate": int((df.label == 0).sum()),
    }
    report["unique_registrable_domains"] = int(df["registrable_domain"].nunique())
    report["unique_hosts"] = int(df["host"].nunique())

    report["class_distribution_by_source"] = (
        df.groupby(["source", "label"]).size().unstack(fill_value=0).to_dict(orient="index")
    )

    report["pct_with_path"] = round(100 * df["has_path"].mean(), 2)
    report["pct_with_path_by_class"] = {
        "phishing": round(100 * df[df.label == 1]["has_path"].mean(), 2),
        "legitimate": round(100 * df[df.label == 0]["has_path"].mean(), 2),
    }
    report["pct_with_query"] = round(100 * df["has_query"].mean(), 2)
    report["pct_with_query_by_class"] = {
        "phishing": round(100 * df[df.label == 1]["has_query"].mean(), 2),
        "legitimate": round(100 * df[df.label == 0]["has_query"].mean(), 2),
    }
    report["pct_www"] = round(100 * df["uses_www"].mean(), 2)

    report["top_20_tlds"] = df["tld"].value_counts().head(20).to_dict()
    report["host_length_stats"] = df["host_len"].describe().round(2).to_dict()

    # Domains appearing under BOTH labels (label noise / ambiguous domains)
    dom_labels = df.groupby("registrable_domain")["label"].nunique()
    ambiguous = dom_labels[dom_labels > 1]
    report["registrable_domains_with_both_labels"] = int(len(ambiguous))

    # How many registrable domains contribute >1 URL (matters for domain-disjoint splitting)
    dom_counts = df["registrable_domain"].value_counts()
    report["registrable_domains_with_multiple_urls"] = int((dom_counts > 1).sum())
    report["max_urls_from_single_domain"] = int(dom_counts.max())
    report["top_10_domains_by_url_count"] = dom_counts.head(10).to_dict()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("=== PHASE 1 AUDIT (real, measured) ===")
    for k, v in report.items():
        if isinstance(v, dict) and len(v) > 12:
            logger.info("%s: <%d entries, see %s>", k, len(v), OUT)
        else:
            logger.info("%s: %s", k, v)
    logger.info("Full report written to %s", OUT)
    return report


if __name__ == "__main__":
    audit()
