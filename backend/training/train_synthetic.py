"""
Trains the PRIMARY URL classifiers (Random Forest, XGBoost, SVM) on the
SYNTHETIC dataset (datasets/synthetic/synthetic_urls.csv) using the
extended feature set in app/features/synthetic_features.py.

The original real-data models in artifacts/*.pkl are NOT touched -- they
remain on disk as the backup scorer (see app/models/classifier.py).
Everything here is written to artifacts/synthetic/.

Usage (from backend/):
    python -m datasets.synthetic_generator      # only if the CSV is missing/stale
    python -m training.train_synthetic

Honesty notes baked into the outputs:
  * Test accuracy is on DOMAIN-DISJOINT synthetic data (no domain appears
    in more than one split) AND on a second corpus generated from a
    different random seed.
  * A read-only sanity check against the 67 real URLs in
    datasets/hard_negatives.csv is reported separately. Real data is never
    used for fitting here.
"""
import json
import logging
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, brier_score_loss, confusion_matrix, f1_score,
    matthews_corrcoef, precision_score, recall_score, roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from app.config import settings
from app.features.synthetic_features import SYNTHETIC_FEATURE_NAMES, extract_synthetic_features
from app.services.url_service import normalize_url
from datasets.synthetic_generator import OUT_FILE, generate

import warnings
warnings.filterwarnings("ignore", message="y_pred contains classes not in y_true")
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("phishscan.train_synthetic")

SYN_DIR = settings.SYNTHETIC_ARTIFACTS_DIR
SYN_DIR.mkdir(parents=True, exist_ok=True)
SEED = 42


def featurize(urls) -> np.ndarray:
    """Features are computed on the NORMALIZED url -- exactly what the live
    API scores (normalize_url in url_service) -- so train == inference."""
    rows = []
    for u in urls:
        n = normalize_url(str(u)) or str(u)
        f = extract_synthetic_features(n)
        rows.append([float(f[k]) for k in SYNTHETIC_FEATURE_NAMES])
    return np.array(rows, dtype=float)


def metrics(y, probs, thr) -> dict:
    preds = (probs >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y)),
        "accuracy": round(accuracy_score(y, preds), 4),
        "balanced_accuracy": round(balanced_accuracy_score(y, preds), 4),
        "precision": round(precision_score(y, preds, zero_division=0), 4),
        "recall": round(recall_score(y, preds, zero_division=0), 4),
        "f1": round(f1_score(y, preds, zero_division=0), 4),
        "mcc": round(matthews_corrcoef(y, preds), 4) if len(set(y)) > 1 else None,
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "false_negative_rate": round(fn / max(1, fn + tp), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if len(set(y)) > 1:
        out["roc_auc"] = round(roc_auc_score(y, probs), 4)
        out["brier_score"] = round(brier_score_loss(y, probs), 4)
    return out


def pick_threshold(y, probs) -> float:
    best_t, best_f = 0.5, -1
    for t in np.linspace(0.05, 0.95, 91):
        f = f1_score(y, (probs >= t).astype(int), zero_division=0)
        if f > best_f:
            best_f, best_t = f, t
    return round(float(best_t), 3)


def main():
    if not OUT_FILE.exists():
        log.info("synthetic_urls.csv missing -- generating it first")
        OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        generate(80000, SEED).to_csv(OUT_FILE, index=False)
    df = pd.read_csv(OUT_FILE)
    log.info("Loaded %d synthetic URLs (%d phishing / %d legitimate)", len(df), int(df.label.sum()), int((1 - df.label).sum()))

    parts = {s: df[df.split == s].reset_index(drop=True) for s in ("train", "val", "test")}
    X = {s: featurize(p["url"]) for s, p in parts.items()}
    y = {s: p["label"].values for s, p in parts.items()}

    # --- fit
    rf = RandomForestClassifier(n_estimators=150, max_depth=18, min_samples_leaf=2, class_weight="balanced", random_state=SEED, n_jobs=-1)
    rf.fit(X["train"], y["train"])
    models = {"random_forest": rf}

    try:
        from xgboost import XGBClassifier
        xgb = XGBClassifier(n_estimators=250, max_depth=7, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9, eval_metric="logloss", random_state=SEED, n_jobs=-1)
        xgb.fit(X["train"], y["train"])
        models["xgboost"] = xgb
    except ImportError:
        log.warning("xgboost not installed -- skipping")

    rng = np.random.default_rng(SEED)
    idx = rng.choice(len(X["train"]), size=min(20000, len(X["train"])), replace=False)
    scaler = StandardScaler().fit(X["train"][idx])
    svm = SVC(kernel="rbf", C=3.0, probability=True, class_weight="balanced", random_state=SEED)
    svm.fit(scaler.transform(X["train"][idx]), y["train"][idx])
    models["svm"] = svm

    def proba(name, Xm):
        return models[name].predict_proba(scaler.transform(Xm) if name == "svm" else Xm)[:, 1]

    # --- thresholds on VAL only, then evaluate
    # second corpus, different seed: different domains, names, paths
    alt = generate(30000, 1337)
    alt = alt[alt.split.isin(["test", "val", "train"])].reset_index(drop=True)
    X_alt, y_alt = featurize(alt["url"]), alt["label"].values

    # real, read-only sanity set
    hn_path = Path("datasets/hard_negatives.csv")
    X_hn = y_hn = None
    if hn_path.exists():
        hn = pd.read_csv(hn_path)
        X_hn, y_hn = featurize(hn["url"]), hn["label"].values

    meta_models, rows = {}, []
    for name in models:
        thr = pick_threshold(y["val"], proba(name, X["val"]))
        ev = {"synthetic_domain_disjoint_test": metrics(y["test"], proba(name, X["test"]), thr),
              "synthetic_alt_seed_corpus": metrics(y_alt, proba(name, X_alt), thr)}
        if X_hn is not None:
            ev["real_hard_negatives_sanity"] = metrics(y_hn, proba(name, X_hn), thr)
        meta_models[name] = {"locked_threshold": thr, "evaluations": ev}
        for k, m in ev.items():
            rows.append({"model": name, "evaluated_on": k, **{a: b for a, b in m.items() if a != "confusion_matrix"}})
            log.info("%-14s %-34s acc=%.4f f1=%.4f fpr=%.4f fnr=%.4f", name, k, m["accuracy"], m["f1"], m["false_positive_rate"], m["false_negative_rate"])

    # ensemble (what the API actually serves): mean of model probabilities
    def ens(Xm):
        return np.mean([proba(n, Xm) for n in models], axis=0)

    ens_thr = pick_threshold(y["val"], ens(X["val"]))
    ens_ev = {"synthetic_domain_disjoint_test": metrics(y["test"], ens(X["test"]), ens_thr),
              "synthetic_alt_seed_corpus": metrics(y_alt, ens(X_alt), ens_thr)}
    if X_hn is not None:
        ens_ev["real_hard_negatives_sanity"] = metrics(y_hn, ens(X_hn), ens_thr)
        flagged = hn["url"][ens(X_hn) >= ens_thr].tolist()
        log.info("Real hard negatives flagged by ensemble (%d/%d): %s", len(flagged), len(hn), flagged)
    meta_models["ensemble_mean"] = {"locked_threshold": ens_thr, "evaluations": ens_ev}
    for k, m in ens_ev.items():
        rows.append({"model": "ensemble_mean", "evaluated_on": k, **{a: b for a, b in m.items() if a != "confusion_matrix"}})
        log.info("%-14s %-34s acc=%.4f f1=%.4f fpr=%.4f fnr=%.4f", "ensemble_mean", k, m["accuracy"], m["f1"], m["false_positive_rate"], m["false_negative_rate"])

    # per-category breakdown on test (ensemble)
    te = parts["test"].copy()
    te["p"] = ens(X["test"])
    te["pred"] = (te["p"] >= ens_thr).astype(int)
    te["correct"] = (te["pred"] == te["label"]).astype(int)
    per_cat = te.groupby(["label", "category"])["correct"].agg(["mean", "count"]).round(4).reset_index()
    per_cat.columns = ["label", "category", "accuracy", "n"]
    per_cat.to_csv(SYN_DIR / "per_category_test_accuracy.csv", index=False)
    log.info("\n%s", per_cat.to_string(index=False))

    # --- save
    with open(SYN_DIR / "rf.pkl", "wb") as f:
        pickle.dump(rf, f)
    if "xgboost" in models:
        with open(SYN_DIR / "xgboost.pkl", "wb") as f:
            pickle.dump(models["xgboost"], f)
    with open(SYN_DIR / "svm.pkl", "wb") as f:
        pickle.dump(svm, f)
    with open(SYN_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    pd.DataFrame(rows).to_csv(SYN_DIR / "synthetic_results.csv", index=False)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "feature_version": "synthetic_features_v1",
        "feature_names": SYNTHETIC_FEATURE_NAMES,
        "training_data": "datasets/synthetic/synthetic_urls.csv (fully synthetic; real datasets not used for fitting)",
        "split_strategy": "domain_disjoint",
        "random_seed": SEED,
        "dataset_sizes": {s: int(len(p)) for s, p in parts.items()} | {"alt_seed_corpus": int(len(alt)), "real_hard_negatives": None if y_hn is None else int(len(y_hn))},
        "ensemble_threshold": ens_thr,
        "models": meta_models,
        "notes": [
            "Primary scorer. The original real-data models in artifacts/ are the backup (see app/models/classifier.py).",
            "Accuracy figures describe synthetic data. real_hard_negatives_sanity is a small read-only check on real URLs, not a real-world accuracy claim.",
        ],
    }
    with open(SYN_DIR / "model_metadata.json", "w") as f:
        json.dump(meta, f, indent=2, default=str)
    log.info("Saved synthetic artifacts to %s", SYN_DIR)


if __name__ == "__main__":
    main()
