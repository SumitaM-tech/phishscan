"""
Builds the URL-level training corpus from the real, previously-
downloaded historical datasets in datasets/historical_sources/ (a
PhishTank bulk CSV export + the PhiUSIIL dataset). Writes to
datasets/raw/historical_*.csv -- named with a "historical_" prefix
specifically so it's never confused with datasets/raw/live_*.csv,
which datasets/export_raw.py produces from the separate real-time
threat-intelligence sync pipeline.

This script only reads from historical_sources/ and never modifies
those files. Run it whenever you add or replace a file there:

    python -m datasets.build_training_corpus
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from datasets.loaders import load_historical_phishtank_csv, load_phiusiil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.build_training_corpus")

RAW_DIR = Path(__file__).resolve().parent / "raw"


def _augment_www_variants(legit_df: "pd.DataFrame") -> "pd.DataFrame":
    """PhiUSIIL's legitimate URLs are overwhelmingly www.-prefixed
    while the phishing sources (PhishTank especially) are overwhelmingly
    bare-apex domains -- left as-is, a model trained on this corpus
    learns "missing www." as a phishing shortcut, which misfires on
    real bare-apex sites (github.com, most modern SPAs, etc). For every
    www.-prefixed legitimate URL already in the real dataset, this adds
    its bare-apex equivalent as an additional legitimate example --
    not a new/fabricated domain, just the same real site's other valid
    form -- to remove that spurious correlation instead of the model
    learning it.
    """
    import re
    import pandas as pd

    www_rows = legit_df[legit_df["url"].str.contains(r"^https?://www\.", regex=True, na=False)]
    bare_urls = www_rows["url"].apply(lambda u: re.sub(r"^(https?://)www\.", r"\1", u))
    augmented = pd.DataFrame({"url": bare_urls, "label": 0, "source": "phiusiil_www_stripped"})
    augmented = augmented.drop_duplicates(subset="url")
    logger.info("Augmented %d bare-apex legitimate examples from www.-prefixed PhiUSIIL URLs (bias mitigation)", len(augmented))
    return pd.concat([legit_df, augmented], ignore_index=True)


def main():
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    phishtank_hist = load_historical_phishtank_csv()
    phiusiil = load_phiusiil()

    phishing_frames = []
    legitimate_frames = []

    if len(phishtank_hist) > 0:
        phishing_frames.append(phishtank_hist)
    if len(phiusiil) > 0:
        phishing_frames.append(phiusiil[phiusiil.label == 1])
        legitimate_frames.append(phiusiil[phiusiil.label == 0])

    if not phishing_frames and not legitimate_frames:
        logger.error(
            "No historical datasets found in %s. Expected a PhishTank CSV "
            "(*phishtank*.csv) and/or the PhiUSIIL zip (*phiusiil*.zip).",
            Path(__file__).resolve().parent / "historical_sources",
        )
        return

    import pandas as pd

    phishing_df = pd.concat(phishing_frames, ignore_index=True) if phishing_frames else pd.DataFrame(columns=["url", "label", "source"])
    legit_df = pd.concat(legitimate_frames, ignore_index=True) if legitimate_frames else pd.DataFrame(columns=["url", "label", "source"])

    if len(legit_df) > 0:
        legit_df = _augment_www_variants(legit_df)

    phishing_path = RAW_DIR / "historical_phishing.csv"
    legit_path = RAW_DIR / "historical_legitimate.csv"
    phishing_df.to_csv(phishing_path, index=False)
    legit_df.to_csv(legit_path, index=False)

    logger.info("Wrote %d historical phishing URLs -> %s", len(phishing_df), phishing_path)
    if len(phishing_frames) > 1 or (phishtank_hist is not None and len(phishtank_hist) and len(phiusiil) and (phiusiil.label == 1).sum()):
        for src, count in phishing_df.groupby("source").size().items():
            logger.info("  - %s: %d", src, count)
    logger.info("Wrote %d historical legitimate URLs -> %s", len(legit_df), legit_path)
    for src, count in legit_df.groupby("source").size().items() if len(legit_df) else []:
        logger.info("  - %s: %d", src, count)


if __name__ == "__main__":
    main()
