"""
Bridges the live system (ThreatIntelRecord, kept fresh by the feed
scheduler) and the offline training pipeline (which reads flat files
from datasets/raw/, per spec).

Run this whenever you want to refresh training data from whatever
has been synced so far:

    python -m datasets.export_raw

It does NOT hit PhishTank/OpenPhish itself -- that's the scheduler's
job (app/scheduler.py) or `POST /api/threat-intelligence/sync`. This
script only snapshots what's already in the database, plus a fresh
pull of the (non-phishing) Tranco legitimate-domain list.

Output is named datasets/raw/live_*.csv -- deliberately distinct from
datasets/raw/historical_*.csv (written by build_training_corpus.py
from datasets/historical_sources/) so the two pipelines' outputs are
never confused with each other, per spec. preprocess.py combines
whichever of the two are present.
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
from app.database.database import SessionLocal
from app.database import models
from datasets.loaders import fetch_legitimate_urls

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.export_raw")

RAW_DIR = Path(__file__).resolve().parent / "raw"


def export_phishing_urls() -> pd.DataFrame:
    db = SessionLocal()
    try:
        rows = db.query(models.ThreatIntelRecord).all()
        if not rows:
            logger.warning(
                "No ThreatIntelRecord rows found. Run `POST /api/threat-intelligence/sync` "
                "(or start the API with ENABLE_FEED_SCHEDULER=true and SYNC_ON_STARTUP=true) "
                "and wait for a sync to complete before exporting."
            )
        df = pd.DataFrame([
            {"url": r.url, "label": 1, "source": f"live_{r.source}"}
            for r in rows
        ])
        return df
    finally:
        db.close()


def main(legitimate_limit: int = 5000):
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    phishing_df = export_phishing_urls()
    phishing_path = RAW_DIR / "live_phishing.csv"
    phishing_df.to_csv(phishing_path, index=False)
    logger.info("Exported %d phishing URLs (from synced threat-intel feeds) -> %s", len(phishing_df), phishing_path)

    legit_df = fetch_legitimate_urls(limit=legitimate_limit)
    legit_path = RAW_DIR / "live_legitimate.csv"
    legit_df.to_csv(legit_path, index=False)
    logger.info("Exported %d legitimate URLs (from Tranco) -> %s", len(legit_df), legit_path)

    if len(phishing_df) == 0 and len(legit_df) == 0:
        logger.warning(
            "Both live sources are empty. That's fine if datasets/raw/historical_*.csv "
            "(from `python -m datasets.build_training_corpus`) has real data -- "
            "preprocess.py combines whatever it finds."
        )


if __name__ == "__main__":
    main()

