"""
Phase 1/9/10/16: traditional baselines (Random Forest, XGBoost, SVM),
trained BOTH the old way (random URL split) and the new way
(domain-disjoint split), then evaluated identically on multiple real
held-out sets so the difference is measured, not asserted:

  - domain-disjoint test  (test.csv)          -- the honest generalization number
  - random-split test     (test_random.csv)   -- what the OLD pipeline reported
  - temporal test         (test_temporal.csv) -- train-on-old, test-on-newer
  - hard negatives        (hard_negatives.csv) -- real branded URLs w/ paths

Threshold selection is fit ONLY on the domain-disjoint validation
set, then locked before touching any test set (Phase 10/17: never
tune on the test set).

Usage:
    python -m training.train_baselines
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
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    average_precision_score, balanced_accuracy_score, matthews_corrcoef,
    brier_score_loss, confusion_matrix,
)

from app.config import settings
from app.features.url_features import FEATURE_NAMES, extract_url_features

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.train_baselines")

PROCESSED = Path("datasets/processed")
ARTIFACTS = settings.ARTIFACTS_DIR
ARTIFACTS.mkdir(parents=True, exist_ok=True)


def _load(name: str) -> pd.DataFrame | None:
    path = PROCESSED / f"{name}.csv"
    if not path.exists():
        return None
    return pd.read_csv(path)


def _xy(df: pd.DataFrame):
    return df[FEATURE_NAMES].values, df["label"].values


def _load_hard_negatives() -> pd.DataFrame | None:
    path = Path("datasets/hard_negatives.csv")
    if not path.exists():
        return None
    df = pd.read_csv(path)
    rows = [extract_url_features(u) for u in df["url"]]
    feat = pd.DataFrame(rows)
    feat["label"] = df["label"].values
    feat["url"] = df["url"].values
    return feat


def full_metrics(y_true, preds, probs) -> dict:
    cm = confusion_matrix(y_true, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    m = {
        "n": int(len(y_true)),
        "accuracy": round(accuracy_score(y_true, preds), 4),
        "balanced_accuracy": round(balanced_accuracy_score(y_true, preds), 4),
        "precision": round(precision_score(y_true, preds, zero_division=0), 4),
        "recall": round(recall_score(y_true, preds, zero_division=0), 4),
        "f1": round(f1_score(y_true, preds, zero_division=0), 4),
        "mcc": round(matthews_corrcoef(y_true, preds), 4) if len(set(y_true)) > 1 else None,
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "false_negative_rate": round(fn / max(1, fn + tp), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    try:
        m["roc_auc"] = round(roc_auc_score(y_true, probs), 4)
        m["pr_auc"] = round(average_precision_score(y_true, probs), 4)
        m["brier_score"] = round(brier_score_loss(y_true, probs), 4)
    except ValueError:
        m["roc_auc"] = m["pr_auc"] = m["brier_score"] = None
    return m


def pick_threshold(y_val, probs_val, target: str) -> float:
    """Selects an operating threshold on VALIDATION data only. Never
    touches test data (Phase 10/17)."""
    thresholds = np.linspace(0.01, 0.99, 197)
    best_t, best_score = 0.5, -1
    for t in thresholds:
        preds = (probs_val >= t).astype(int)
        if target == "high_precision":
            p = precision_score(y_val, preds, zero_division=0)
            score = recall_score(y_val, preds, zero_division=0) if p >= 0.99 else -1
        elif target == "high_recall":
            r = recall_score(y_val, preds, zero_division=0)
            score = precision_score(y_val, preds, zero_division=0) if r >= 0.98 else -1
        else:  # balanced -> maximize F1
            score = f1_score(y_val, preds, zero_division=0)
        if score > best_score:
            best_score, best_t = score, t
    return round(float(best_t), 3)


def _xgb():
    try:
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=42)
    except ImportError:
        logger.warning("xgboost not installed -- skipping")
        return None


def run_pipeline_for_split(X_train, y_train, save_artifacts: bool):
    """Trains RF/XGBoost/SVM on one split's train set. Returns
    {model_name: fitted_model} (SVM entry is a (model, scaler) tuple)."""
    fitted = {}

    rf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, class_weight="balanced")
    rf.fit(X_train, y_train)
    fitted["random_forest"] = rf

    xgb = _xgb()
    if xgb is not None:
        xgb.fit(X_train, y_train)
        fitted["xgboost"] = xgb

    SVM_MAX_ROWS = 20000
    if len(X_train) > SVM_MAX_ROWS:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X_train), size=SVM_MAX_ROWS, replace=False)
        X_svm, y_svm = X_train[idx], y_train[idx]
    else:
        X_svm, y_svm = X_train, y_train
    scaler = StandardScaler().fit(X_svm)
    svm = SVC(kernel="rbf", probability=True, class_weight="balanced", random_state=42)
    svm.fit(scaler.transform(X_svm), y_svm)
    fitted["svm"] = (svm, scaler)

    if save_artifacts:
        with open(settings.RF_MODEL_PATH, "wb") as f:
            pickle.dump(rf, f)
        if "xgboost" in fitted:
            with open(settings.XGB_MODEL_PATH, "wb") as f:
                pickle.dump(xgb, f)
        with open(settings.SVM_MODEL_PATH, "wb") as f:
            pickle.dump(svm, f)
        with open(ARTIFACTS / "scaler.pkl", "wb") as f:
            pickle.dump(scaler, f)

    return fitted


def predict_proba_any(fitted_entry, X):
    if isinstance(fitted_entry, tuple):
        model, scaler = fitted_entry
        return model.predict_proba(scaler.transform(X))[:, 1]
    return fitted_entry.predict_proba(X)[:, 1]


def main():
    train = _load("train")
    val = _load("val")
    test = _load("test")
    if train is None:
        raise FileNotFoundError("datasets/processed/train.csv not found -- run `python -m datasets.preprocess` first")

    X_train, y_train = _xy(train)
    X_val, y_val = _xy(val)
    X_test, y_test = _xy(test)

    logger.info("=== Training on DOMAIN-DISJOINT split (%d rows) -- deployed models ===", len(train))
    fitted_new = run_pipeline_for_split(X_train, y_train, save_artifacts=True)

    train_r = _load("train_random")
    fitted_old = None
    if train_r is not None:
        logger.info("=== Training on RANDOM split (%d rows, old method) -- comparison only, NOT deployed ===", len(train_r))
        Xr_train, yr_train = _xy(train_r)
        fitted_old = run_pipeline_for_split(Xr_train, yr_train, save_artifacts=False)

    temporal_test = _load("test_temporal")
    hard_neg = _load_hard_negatives()
    test_random = _load("test_random")

    comparison_rows = []
    metadata_models = {}

    for name, entry in fitted_new.items():
        probs_val = predict_proba_any(entry, X_val)
        thresholds = {
            "high_precision": pick_threshold(y_val, probs_val, "high_precision"),
            "balanced": pick_threshold(y_val, probs_val, "balanced"),
            "high_recall": pick_threshold(y_val, probs_val, "high_recall"),
        }
        locked_threshold = thresholds["balanced"]

        eval_sets = {"domain_disjoint_test": (X_test, y_test)}
        if test_random is not None:
            eval_sets["random_split_test"] = _xy(test_random)
        if temporal_test is not None:
            eval_sets["temporal_test"] = _xy(temporal_test)
        if hard_neg is not None:
            eval_sets["hard_negatives"] = _xy(hard_neg)

        model_metrics = {"thresholds": thresholds, "locked_threshold": locked_threshold, "evaluations": {}}
        for set_name, (Xe, ye) in eval_sets.items():
            probs_e = predict_proba_any(entry, Xe)
            preds_e = (probs_e >= locked_threshold).astype(int)
            m = full_metrics(ye, preds_e, probs_e)
            model_metrics["evaluations"][set_name] = m
            logger.info("[NEW/domain-disjoint] %s on %s: acc=%s f1=%s roc_auc=%s fpr=%s fnr=%s",
                        name, set_name, m["accuracy"], m["f1"], m["roc_auc"], m["false_positive_rate"], m["false_negative_rate"])
            row = {"model": name, "split_trained_on": "domain_disjoint", "evaluated_on": set_name}
            row.update({k: v for k, v in m.items() if k != "confusion_matrix"})
            comparison_rows.append(row)

        metadata_models[name] = model_metrics

        if fitted_old is not None and name in fitted_old:
            probs_dd = predict_proba_any(fitted_old[name], X_test)
            preds_dd = (probs_dd >= 0.5).astype(int)
            m = full_metrics(y_test, preds_dd, probs_dd)
            logger.info("[OLD/random-trained model evaluated on domain-disjoint test] %s: acc=%s f1=%s roc_auc=%s fpr=%s fnr=%s",
                        name, m["accuracy"], m["f1"], m["roc_auc"], m["false_positive_rate"], m["false_negative_rate"])
            row = {"model": name, "split_trained_on": "random", "evaluated_on": "domain_disjoint_test"}
            row.update({k: v for k, v in m.items() if k != "confusion_matrix"})
            comparison_rows.append(row)

            if test_random is not None:
                Xtr, ytr = _xy(test_random)
                probs_rr = predict_proba_any(fitted_old[name], Xtr)
                preds_rr = (probs_rr >= 0.5).astype(int)
                m2 = full_metrics(ytr, preds_rr, probs_rr)
                logger.info("[OLD/random-trained model on random test -- what the OLD pipeline actually reported] %s: acc=%s f1=%s",
                            name, m2["accuracy"], m2["f1"])
                row2 = {"model": name, "split_trained_on": "random", "evaluated_on": "random_split_test"}
                row2.update({k: v for k, v in m2.items() if k != "confusion_matrix"})
                comparison_rows.append(row2)

            if hard_neg is not None:
                Xh, yh = _xy(hard_neg)
                probs_h = predict_proba_any(fitted_old[name], Xh)
                preds_h = (probs_h >= 0.5).astype(int)
                m3 = full_metrics(yh, preds_h, probs_h)
                row3 = {"model": name, "split_trained_on": "random", "evaluated_on": "hard_negatives"}
                row3.update({k: v for k, v in m3.items() if k != "confusion_matrix"})
                comparison_rows.append(row3)

    results_df = pd.DataFrame(comparison_rows)
    results_df.to_csv(ARTIFACTS / "baseline_results.csv", index=False)
    results_df.to_csv(ARTIFACTS / "old_vs_new_comparison.csv", index=False)

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "feature_version": "url_features_v1_host_only_19feat",
        "feature_names": FEATURE_NAMES,
        "split_strategy_deployed": "domain_disjoint",
        "random_seed": 42,
        "dataset_sizes": {
            "train": int(len(train)), "val": int(len(val)), "test": int(len(test)),
            "test_random": int(len(test_random)) if test_random is not None else None,
            "test_temporal": int(len(temporal_test)) if temporal_test is not None else None,
            "hard_negatives": int(len(hard_neg)) if hard_neg is not None else None,
        },
        "models": metadata_models,
        "known_limitations": [
            "GNN infrastructure model could not be trained on real DNS/RDAP/TLS/CT graph data in this "
            "sandboxed environment (no live network access to those services here) -- see README.",
            "Hard-negative set is a small (66-URL) hand-curated list of real, well-known branded URLs, "
            "not a large crawled sample -- adequate to catch gross login/verify-keyword shortcuts, not a "
            "substitute for a large real-world red-team URL corpus.",
            "Temporal split is fully real only for the phishing class (PhishTank submission_time); the "
            "legitimate class (PhiUSIIL) carries no timestamp, so temporal drift in legitimate site "
            "structure is not measured.",
        ],
    }
    with open(ARTIFACTS / "model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2, default=str)

    logger.info("\n%s", results_df.to_string(index=False))
    logger.info("Saved artifacts to %s (model_metadata.json, old_vs_new_comparison.csv)", ARTIFACTS)


if __name__ == "__main__":
    main()
