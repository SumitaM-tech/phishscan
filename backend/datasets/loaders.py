"""
Three kinds of dataset input, deliberately kept separate:

1. Historical bulk sources (datasets/historical_sources/) -- real,
   previously-downloaded datasets provided as project files: a
   PhishTank CSV export and the PhiUSIIL URL dataset. These are read
   LOCALLY and are never modified by this code (loaders only ever
   open them for reading). This is the primary corpus for
   datasets/build_training_corpus.py. Entirely separate from the live
   PhishTank/OpenPhish sync pipeline (app/services/threat_intel_service.py),
   per spec -- that pipeline keeps running against the live feeds on
   its own schedule regardless of what's in historical_sources/.

2. UCI "Phishing Websites" -- a static, pre-extracted-feature
   benchmark dataset (30 categorical features + Result label, no raw
   URL string). Read locally if present in historical_sources/
   (matched by filename pattern), else fetched over the network as a
   fallback. Used only for the standalone baseline comparison in
   training/evaluate_uci_baseline.py -- it has no URL text, so it
   cannot feed the Transformer/GNN corpus.

3. A live legitimate/benign domain list (Tranco), fetched over the
   network -- used only as a fallback negative-class source if
   PhiUSIIL isn't available, since PhishTank/OpenPhish only ever
   report positives.

None of this is synthetic or hardcoded: (1) and (2) are real,
user-provided downloads read from disk; (3) is fetched live. The
live threat-intel sync corpus (ThreatIntelRecord -> datasets/raw/live_*.csv)
is produced separately by datasets/export_raw.py.
"""
import io
import logging
import zipfile
from pathlib import Path

import pandas as pd
import requests

from app.config import settings

HERE = Path(__file__).resolve().parent
RAW_DIR = HERE / "raw"
HISTORICAL_DIR = HERE / "historical_sources"
RAW_DIR.mkdir(exist_ok=True, parents=True)

logger = logging.getLogger("phishscan.datasets")

TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"


# --- 1. Historical bulk sources (local, real, read-only) -------------------

def load_historical_phishtank_csv() -> pd.DataFrame:
    """Reads a PhishTank bulk CSV export (phish_id,url,phish_detail_url,
    submission_time,verified,verification_time,online,target -- the
    same schema as the live feed collector) from historical_sources/.
    Every row is phishing by definition of the source."""
    path = _find_historical(["*phishtank*.csv"])
    if not path:
        logger.info("No historical PhishTank CSV found in %s", HISTORICAL_DIR)
        return pd.DataFrame(columns=["url", "label", "source"])

    df = pd.read_csv(path)
    out = pd.DataFrame({
        "url": df["url"].astype(str),
        "label": 1,
        "source": "phishtank_historical",
    })
    logger.info("Loaded %d rows from historical PhishTank CSV (%s)", len(out), path.name)
    return out


def load_phiusiil() -> pd.DataFrame:
    """Reads the PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024)
    from historical_sources/. Its own label convention is 1=legitimate,
    0=phishing -- inverted from this app's convention (1=phishing) --
    so it's flipped here at load time. Real URLs for BOTH classes, so
    this is also the primary legitimate-URL source for training."""
    path = _find_historical(["*phiusiil*.zip", "*phiusiil*.csv"])
    if not path:
        logger.info("No PhiUSIIL dataset found in %s", HISTORICAL_DIR)
        return pd.DataFrame(columns=["url", "label", "source"])

    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            inner = next(n for n in zf.namelist() if n.endswith(".csv"))
            with zf.open(inner) as f:
                df = pd.read_csv(f, usecols=["URL", "label"])
    else:
        df = pd.read_csv(path, usecols=["URL", "label"])

    out = pd.DataFrame({
        "url": df["URL"].astype(str),
        "label": 1 - df["label"].astype(int),  # flip: PhiUSIIL 1=legit -> ours 1=phishing
        "source": "phiusiil",
    })
    logger.info(
        "Loaded %d rows from PhiUSIIL (%s): %d phishing, %d legitimate",
        len(out), path.name, int((out.label == 1).sum()), int((out.label == 0).sum()),
    )
    return out


def load_historical_corpus() -> pd.DataFrame:
    """Combines every historical source found on disk. This is the
    main entry point for datasets/build_training_corpus.py."""
    frames = [load_historical_phishtank_csv(), load_phiusiil()]
    frames = [f for f in frames if len(f) > 0]
    if not frames:
        return pd.DataFrame(columns=["url", "label", "source"])
    return pd.concat(frames, ignore_index=True)


# --- 2. UCI baseline (local-first, network fallback) ------------------------

def load_uci_phishing() -> pd.DataFrame:
    """UCI 'Phishing Websites' dataset: 30 pre-extracted categorical
    features + a Result label, not raw URLs. Baseline-only -- see
    training/evaluate_uci_baseline.py."""
    local = _find_historical(["*.arff", "Training Dataset.arff"], zip_patterns=["*phishing_websites*.zip", "*uci*.zip"])
    if local is not None:
        text = local.read_text(errors="ignore") if isinstance(local, Path) else local
        df = _parse_arff(text)
        logger.info("Loaded %d rows from local UCI ARFF file", len(df))
        return df

    dest = RAW_DIR / "uci_phishing.zip"
    if _download(settings.UCI_PHISHING_URL, dest):
        try:
            with zipfile.ZipFile(dest) as zf:
                inner = next(n for n in zf.namelist() if n.endswith(".csv") or n.endswith(".arff"))
                with zf.open(inner) as f:
                    content = f.read()
            if inner.endswith(".csv"):
                return pd.read_csv(io.BytesIO(content))
            return _parse_arff(content.decode(errors="ignore"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed parsing UCI dataset: %s", exc)
    return pd.DataFrame()


# --- 3. Live legitimate fallback (network) ----------------------------------

def fetch_legitimate_urls(limit: int = 5000) -> pd.DataFrame:
    """Downloads the Tranco top-sites ranking. Only used as a fallback
    negative-class source when PhiUSIIL isn't available locally."""
    dest = RAW_DIR / "tranco_top1m.zip"
    if not _download(TRANCO_LIST_URL, dest):
        logger.warning("Could not fetch Tranco list -- returning empty legitimate set")
        return pd.DataFrame(columns=["url", "label", "source"])

    try:
        with zipfile.ZipFile(dest) as zf:
            inner = next(n for n in zf.namelist() if n.endswith(".csv"))
            with zf.open(inner) as f:
                df = pd.read_csv(f, names=["rank", "domain"], nrows=limit)
        urls = "https://" + df["domain"].astype(str) + "/"
        return pd.DataFrame({"url": urls, "label": 0, "source": "tranco"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed parsing Tranco list: %s", exc)
        return pd.DataFrame(columns=["url", "label", "source"])


# --- helpers -----------------------------------------------------------------

def _find_historical(csv_patterns: list[str], zip_patterns: list[str] | None = None) -> Path | None:
    """Locates a file in historical_sources/ by glob pattern. Read-only
    lookup -- never writes to or modifies anything under that directory."""
    if not HISTORICAL_DIR.exists():
        return None
    for pattern in csv_patterns:
        matches = list(HISTORICAL_DIR.glob(pattern))
        if matches:
            return matches[0]
    if zip_patterns:
        for pattern in zip_patterns:
            for zpath in HISTORICAL_DIR.glob(pattern):
                with zipfile.ZipFile(zpath) as zf:
                    arff_names = [n for n in zf.namelist() if n.endswith(".arff")]
                    if not arff_names:
                        continue
                    # Prefer a file named like "Training Dataset.arff" over
                    # legacy/backup variants (e.g. ".old.arff") that some
                    # dataset mirrors bundle alongside the current one --
                    # fall back to the largest .arff by size if no name hints.
                    named = [n for n in arff_names if "training" in n.lower()]
                    if named:
                        chosen = named[0]
                    else:
                        chosen = max(arff_names, key=lambda n: zf.getinfo(n).file_size)
                    with zf.open(chosen) as f:
                        return f.read().decode(errors="ignore")
    return None


def _download(url: str, dest: Path, timeout: int = 60) -> bool:
    if dest.exists() and dest.stat().st_size > 0:
        return True
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "PhishScan-Research/1.0"})
        resp.raise_for_status()
        dest.write_bytes(resp.content)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Download failed for %s: %s", url, exc)
        return False


def _parse_arff(text: str) -> pd.DataFrame:
    lines = text.splitlines()
    attrs, data_start = [], None
    for i, line in enumerate(lines):
        low = line.strip().lower()
        if low.startswith("@attribute"):
            attrs.append(line.split()[1])
        elif low.startswith("@data"):
            data_start = i + 1
            break
    rows = [l.split(",") for l in lines[data_start:] if l.strip()]
    return pd.DataFrame(rows, columns=attrs)
