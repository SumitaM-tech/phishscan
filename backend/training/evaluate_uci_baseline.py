"""
Standalone baseline comparison on the UCI "Phishing Websites" dataset,
using ITS OWN 30 pre-extracted categorical features directly (not our
url_features.py, since that dataset has no raw URL string to extract
from). Kept entirely separate from the main training pipeline
(train_baselines.py / train_semantic.py / train_gnn.py / train_hybrid.py)
per spec -- UCI is a benchmark/reference point, not a training source
for the live app's models.

Usage:
    python -m training.evaluate_uci_baseline
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from app.config import settings
from datasets.loaders import load_uci_phishing

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.evaluate_uci_baseline")


def main():
    df = load_uci_phishing()
    if df.empty or "Result" not in df.columns:
        logger.error(
            "UCI dataset not available (expected a local .arff in "
            "datasets/historical_sources/ or network access to fetch it). Nothing to evaluate."
        )
        return

    df = df.apply(pd.to_numeric, errors="coerce").dropna()
    X = df.drop(columns=["Result"]).values
    y = (df["Result"].astype(int) == 1).astype(int).values  # 1=legitimate, -1=phishing -> 1/0
    logger.info("UCI dataset: %d rows, %d features, phishing=%d legitimate=%d", len(df), X.shape[1], int((y == 0).sum()), int((y == 1).sum()))

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    results = []

    rf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, class_weight="balanced")
    rf.fit(X_train, y_train)
    results.append(_evaluate("random_forest_uci_features", rf, X_test, y_test))

    try:
        from xgboost import XGBClassifier
        xgb = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=42)
        xgb.fit(X_train, y_train)
        results.append(_evaluate("xgboost_uci_features", xgb, X_test, y_test))
    except ImportError:
        logger.warning("xgboost not installed -- skipping")

    scaler = StandardScaler()
    X_train_s, X_test_s = scaler.fit_transform(X_train), scaler.transform(X_test)
    svm = SVC(kernel="rbf", probability=True, class_weight="balanced", random_state=42)
    svm.fit(X_train_s, y_train)
    results.append(_evaluate("svm_uci_features", svm, X_test_s, y_test))

    results_df = pd.DataFrame(results)
    out_path = settings.ARTIFACTS_DIR / "uci_baseline_results.csv"
    results_df.to_csv(out_path, index=False)
    logger.info("\n%s", results_df.to_string(index=False))
    logger.info("Saved to %s -- this is a reference benchmark, not used by the live API.", out_path)


def _evaluate(name: str, model, X_test, y_test) -> dict:
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    metrics = {
        "model": name,
        "accuracy": round(accuracy_score(y_test, preds), 4),
        "precision": round(precision_score(y_test, preds, zero_division=0), 4),
        "recall": round(recall_score(y_test, preds, zero_division=0), 4),
        "f1": round(f1_score(y_test, preds, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, probs), 4),
    }
    logger.info("%s: %s", name, metrics)
    return metrics


if __name__ == "__main__":
    main()
