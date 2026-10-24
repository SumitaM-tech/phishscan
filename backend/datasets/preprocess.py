"""
Preprocessing pipeline: datasets/raw/*.csv -> deduplicated,
normalized, labeled, feature-extracted train/val/test splits.

Auto-discovers every CSV in datasets/raw/ matching the two source
prefixes and combines them:

    historical_phishing.csv / historical_legitimate.csv
        <- python -m datasets.build_training_corpus
        (real bulk datasets from datasets/historical_sources/:
         a PhishTank CSV export + PhiUSIIL)

    live_phishing.csv / live_legitimate.csv
        <- python -m datasets.export_raw
        (a snapshot of the live PhishTank/OpenPhish sync + Tranco)

Either pair alone is enough to build a dataset; when both are
present they're combined and deduplicated by normalized URL, which
is the common case and gives the largest, most accurate training set.
Run at least one of the two export scripts above before this.
"""
import logging
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from sklearn.model_selection import train_test_split, GroupShuffleSplit

from app.services.url_service import normalize_url
from app.features.url_features import extract_url_features, FEATURE_NAMES
from datasets.audit_corpus import registrable_domain

logger = logging.getLogger("phishscan.preprocess")

# Registrable domains that host content for large numbers of unrelated
# third parties (free web builders / URL shorteners / PaaS subdomains).
# A random OR naive domain-disjoint split both mishandle these: random
# split leaks (e.g. many distinct phishing pages under different
# `*.weebly.com` hosts land on both sides and the model partly
# memorizes "weebly.com => legit" or "=> often phishing" instead of
# genuine per-site signal), while grouping strictly by registrable
# domain would pin an outsized, non-representative slice of the whole
# corpus (weebly.com alone is thousands of rows) entirely to one side.
# For these specific known multi-tenant platforms we split at the FULL
# HOST instead (e.g. "evil-page.weebly.com" != "other-page.weebly.com"
# as groups), which is the more honest leakage boundary for shared
# hosting. Everything else groups by registrable domain as usual.
SHARED_HOSTING_SUFFIXES = (
    "weebly.com", "weeblysite.com", "web.app", "firebaseapp.com",
    "repl.co", "wixstudio.com", "wixsite.com", "blogspot.com",
    "github.io", "netlify.app", "vercel.app", "herokuapp.com",
    "000webhostapp.com", "glitch.me", "surge.sh", "pages.dev",
)


def split_group(host: str) -> str:
    for suffix in SHARED_HOSTING_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return host  # group by full host on shared-hosting platforms
    return registrable_domain(host)

RAW_DIR = Path(__file__).resolve().parent / "raw"
PROCESSED_DIR_DEFAULT = Path(__file__).resolve().parent / "processed"

PHISHING_FILES = ["historical_phishing.csv", "live_phishing.csv"]
LEGITIMATE_FILES = ["historical_legitimate.csv", "live_legitimate.csv"]


def load_raw() -> pd.DataFrame:
    frames = []
    for name in PHISHING_FILES + LEGITIMATE_FILES:
        path = RAW_DIR / name
        if path.exists():
            df = pd.read_csv(path)
            if len(df) == 0:
                continue
            frames.append(df)
            logger.info("Found %s: %d rows", name, len(df))
        else:
            logger.info("Not present (skipping): %s", name)

    if not frames:
        raise FileNotFoundError(
            f"No dataset files found in {RAW_DIR}. Run "
            "`python -m datasets.build_training_corpus` (uses datasets/historical_sources/) "
            "and/or `python -m datasets.export_raw` (uses the live-synced database) first."
        )

    return pd.concat(frames, ignore_index=True)


def clean_urls(df: pd.DataFrame) -> pd.DataFrame:
    df = df.drop_duplicates(subset="url").copy()
    df["normalized"] = df["url"].apply(lambda u: normalize_url(str(u)))
    df = df[df["normalized"].notna()]
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    # a URL can appear in more than one source file (e.g. both a
    # historical export and a live sync) -- keep one row per
    # normalized URL, preferring the first (historical, generally
    # larger/more stable) occurrence.
    df = df.drop_duplicates(subset="normalized", keep="first")
    return df.reset_index(drop=True)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extracts features from the NORMALIZED url, not the raw source
    string. This matters: raw URLs are formatted inconsistently across
    sources (e.g. PhishTank rows commonly end in "/", PhiUSIIL's
    legitimate rows commonly don't), which lets a model learn that
    formatting quirk as a spurious "which dataset did this come from"
    shortcut instead of genuine phishing signal. Live inference always
    scores the normalized form (see app/services/url_service.py), so
    training has to match that exactly or the model silently
    miscalibrates on real traffic despite looking fine on held-out
    data drawn from the same raw, inconsistently-formatted sources.
    """
    rows = []
    for row in df.itertuples(index=False):
        feats = extract_url_features(row.normalized)
        feats["url"] = row.url
        feats["label"] = row.label
        feats["source"] = getattr(row, "source", "unknown")
        rows.append(feats)
    out = pd.DataFrame(rows)
    return out[FEATURE_NAMES + ["url", "label", "source"]]


def _prep_common(sample_size: int | None) -> pd.DataFrame:
    raw = load_raw()
    logger.info("Loaded %d raw URLs total from datasets/raw/", len(raw))
    for src, count in raw.groupby("source").size().sort_values(ascending=False).items():
        logger.info("  - %s: %d", src, count)

    cleaned = clean_urls(raw)
    n_phish = int((cleaned.label == 1).sum())
    n_legit = int((cleaned.label == 0).sum())
    logger.info("After cleaning + dedup: %d URLs (phishing=%d, legitimate=%d)", len(cleaned), n_phish, n_legit)
    if n_phish == 0 or n_legit == 0:
        raise ValueError(
            "Need at least one example of each class. Run "
            "`python -m datasets.build_training_corpus` and/or `python -m datasets.export_raw` first."
        )

    if sample_size and len(cleaned) > sample_size:
        frac = sample_size / len(cleaned)
        parts = [g.sample(frac=frac, random_state=42) for _, g in cleaned.groupby("label")]
        cleaned = pd.concat(parts, ignore_index=True)
        logger.info("Stratified-sampled down to %d rows (sample_size=%d)", len(cleaned), sample_size)

    return cleaned


def build_dataset(
    output_dir: Path = PROCESSED_DIR_DEFAULT,
    test_size: float = 0.15,
    val_size: float = 0.15,
    sample_size: int | None = None,
    strategy: str = "domain_disjoint",
    file_tag: str = "",
    extra_legitimate_rows: pd.DataFrame | None = None,
):
    """strategy:
      - "domain_disjoint" (default, used for the deployed model): no
        split_group() value (registrable domain, or full host on
        shared-hosting platforms -- see SHARED_HOSTING_SUFFIXES) is
        allowed to appear in more than one of train/val/test. This is
        the honest leakage-safe split -- the audit found 9,042 groups
        contributing >1 URL (up to 7,767 from a single one), so a
        plain random split would put the same site's URLs on both
        sides of the split and inflate reported accuracy without
        improving real generalization.
      - "random": the OLD behavior (stratified random row split, no
        grouping). Kept only so train_baselines.py can report the
        random-split numbers ALONGSIDE the domain-disjoint numbers for
        an honest before/after comparison -- never used to select the
        deployed model.
    sample_size: if set, stratified-samples down to this many rows
    total after cleaning, before the split. The classical baselines
    (RF/XGBoost) comfortably handle the full real corpus (hundreds of
    thousands of rows); the Transformer/GNN/fusion training loops in
    this project are per-sample (no batching for the graph branch), so
    a bounded sample keeps a full training run to minutes instead of
    hours. Leave as None to use every row.
    file_tag: appended to every output filename (train{file_tag}.csv,
    etc.) so a sampled run (used for the neural models) never
    overwrites the full-corpus run's files (used for the baselines) --
    fixes a real bug where both used to write to the exact same
    train.csv/val.csv/test.csv regardless of sample_size, silently
    swapping out the baselines' full-corpus training data any time
    someone built a sampled split afterward.
    extra_legitimate_rows: optional real, non-fabricated legitimate
    URLs (label=0) to fold into the corpus BEFORE the split -- used to
    correct the brand-representation gap documented in
    datasets/brand_imbalance.py (see build_brand_correction_set()).
    Not duplicated samples: each row here is a distinct real URL not
    already present in the corpus."""
    cleaned = _prep_common(sample_size)
    if extra_legitimate_rows is not None and len(extra_legitimate_rows) > 0:
        before = len(cleaned)
        extra = extra_legitimate_rows.copy()
        extra["normalized"] = extra["url"].apply(lambda u: normalize_url(str(u)))
        extra = extra.dropna(subset=["normalized"])
        extra = extra[~extra["normalized"].isin(cleaned["normalized"])]
        cleaned = pd.concat([cleaned, extra], ignore_index=True)
        logger.info("Folded in %d real brand-correction legitimate URLs (%d after de-dup against existing corpus)",
                    len(extra_legitimate_rows), len(cleaned) - before)
    featured = extract_features(cleaned)

    if strategy == "random":
        train_val, test = train_test_split(featured, test_size=test_size, stratify=featured["label"], random_state=42)
        val_ratio = val_size / (1 - test_size)
        train, val = train_test_split(train_val, test_size=val_ratio, stratify=train_val["label"], random_state=42)
    elif strategy == "domain_disjoint":
        cleaned = cleaned.loc[featured.index] if not featured.index.equals(cleaned.index) else cleaned
        groups = cleaned["normalized"].apply(lambda u: split_group(urlparse(u).hostname or ""))
        groups = groups.reset_index(drop=True)
        featured = featured.reset_index(drop=True)

        gss1 = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
        trainval_idx, test_idx = next(gss1.split(featured, groups=groups))
        train_val, test = featured.iloc[trainval_idx], featured.iloc[test_idx]
        groups_tv = groups.iloc[trainval_idx]

        val_ratio = val_size / (1 - test_size)
        gss2 = GroupShuffleSplit(n_splits=1, test_size=val_ratio, random_state=42)
        train_idx, val_idx = next(gss2.split(train_val, groups=groups_tv))
        train, val = train_val.iloc[train_idx], train_val.iloc[val_idx]

        # Verify no group leaks across splits before writing anything.
        g_train = set(groups_tv.iloc[train_idx])
        g_val = set(groups_tv.iloc[val_idx])
        g_test = set(groups.iloc[test_idx])
        overlap = (g_train & g_val) | (g_train & g_test) | (g_val & g_test)
        if overlap:
            raise RuntimeError(f"Domain-disjoint split leaked {len(overlap)} groups -- aborting, not writing splits.")
        logger.info("Domain-disjoint split verified: 0 groups shared across train/val/test.")
    else:
        raise ValueError(f"Unknown strategy: {strategy!r}")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    strategy_suffix = "" if strategy == "domain_disjoint" else f"_{strategy}"
    suffix = f"{strategy_suffix}{file_tag}"
    train.to_csv(output_dir / f"train{suffix}.csv", index=False)
    val.to_csv(output_dir / f"val{suffix}.csv", index=False)
    test.to_csv(output_dir / f"test{suffix}.csv", index=False)

    logger.info("[%s] Wrote train=%d val=%d test=%d to %s", strategy, len(train), len(val), len(test), output_dir)
    logger.info("[%s] test class balance: phishing=%d legitimate=%d", strategy,
                int((test.label == 1).sum()), int((test.label == 0).sum()))
    return train, val, test


def build_temporal_split(output_dir: Path = PROCESSED_DIR_DEFAULT, sample_size: int | None = None):
    """Temporal holdout: train on older URLs, test on newer ones --
    simulates the real zero-day-detection scenario (Phase 2 spec).
    HONEST LIMITATION: only the PhishTank historical source carries a
    real timestamp (submission_time); PhiUSIIL (the legitimate-URL
    source, and ~40% of the phishing source) has none. So this split
    only reorders the phishing class by real submission date and
    randomly (not temporally -- there is no ground truth to order by)
    assigns the legitimate class and the undated phishing rows,
    stratified to match. This measures "does the model still catch
    NEWER real phishing campaigns it never trained on" -- it does NOT
    measure temporal drift in legitimate-site structure, since no
    dated legitimate corpus was available in this environment (no
    live network access to collect one). Treat this test set as a
    genuine but partial zero-day proxy, not a full temporal audit.
    """
    raw = load_raw()
    cleaned = clean_urls(raw)
    if sample_size and len(cleaned) > sample_size:
        frac = sample_size / len(cleaned)
        parts = [g.sample(frac=frac, random_state=42) for _, g in cleaned.groupby("label")]
        cleaned = pd.concat(parts, ignore_index=True)

    pt = pd.read_csv(RAW_DIR.parent / "historical_sources" / "phishtank_online_valid.csv",
                      usecols=["url", "submission_time"])
    pt["normalized"] = pt["url"].apply(lambda u: normalize_url(str(u)))
    pt = pt.dropna(subset=["normalized"]).drop_duplicates(subset="normalized")
    date_map = dict(zip(pt["normalized"], pd.to_datetime(pt["submission_time"], errors="coerce", utc=True)))

    cleaned["submission_time"] = cleaned["normalized"].map(date_map)
    dated = cleaned[cleaned["submission_time"].notna()].sort_values("submission_time")
    undated = cleaned[cleaned["submission_time"].isna()]

    if len(dated) < 100:
        logger.warning("Fewer than 100 dated rows -- temporal split skipped (not enough real timestamps).")
        return None

    cutoff = dated["submission_time"].quantile(0.85)
    dated_train = dated[dated["submission_time"] <= cutoff]
    dated_test = dated[dated["submission_time"] > cutoff]
    logger.info("Temporal cutoff: %s (train n=%d up to cutoff, test n=%d after)", cutoff, len(dated_train), len(dated_test))

    undated_train, undated_test = train_test_split(undated, test_size=0.15, stratify=undated["label"], random_state=42)

    train = pd.concat([dated_train, undated_train], ignore_index=True)
    test = pd.concat([dated_test, undated_test], ignore_index=True)

    train_f = extract_features(train)
    test_f = extract_features(test)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    train_f.to_csv(output_dir / "train_temporal.csv", index=False)
    test_f.to_csv(output_dir / "test_temporal.csv", index=False)
    logger.info("Wrote temporal train=%d test=%d (dated fraction of test: %.1f%%)",
                len(train_f), len(test_f), 100 * len(dated_test) / max(1, len(test_f)))
    return train_f, test_f


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-size", type=int, default=None, help="Stratified-sample down to this many rows total (default: use every row)")
    parser.add_argument("--also-random", action="store_true", help="Also write the old random-split files (train_random.csv etc.) for an honest before/after comparison")
    parser.add_argument("--also-temporal", action="store_true", help="Also write a temporal holdout (train_temporal.csv / test_temporal.csv)")
    parser.add_argument("--file-tag", default="", help="Suffix for every output filename, so a sampled run never overwrites the full-corpus run's files (e.g. --file-tag _nn for the neural-model training split)")
    parser.add_argument("--with-brand-correction", action="store_true", help="Fold in real, non-fabricated brand-domain legitimate URLs before splitting (see datasets/brand_imbalance.py) -- use for the neural-model split, not the baseline split")
    args = parser.parse_args()

    extra = None
    if args.with_brand_correction:
        from datasets.brand_imbalance import build_brand_correction_set
        extra = build_brand_correction_set()

    build_dataset(sample_size=args.sample_size, strategy="domain_disjoint", file_tag=args.file_tag, extra_legitimate_rows=extra)
    if args.also_random:
        build_dataset(sample_size=args.sample_size, strategy="random", file_tag=args.file_tag, extra_legitimate_rows=extra)
    if args.also_temporal:
        build_temporal_split(sample_size=args.sample_size)
