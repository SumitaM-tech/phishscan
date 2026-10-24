"""
Consolidates results from every trained model into one comparison
table for the ablation study section of your report:
RF vs XGBoost vs SVM vs Transformer-only vs GNN-only vs Hybrid.

Usage:
    python -m training.evaluate
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd
from app.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.evaluate")


def main():
    rows = []

    baseline_path = settings.ARTIFACTS_DIR / "baseline_results.csv"
    if baseline_path.exists():
        rows.append(pd.read_csv(baseline_path))

    for name, path in [
        ("transformer_only", settings.ARTIFACTS_DIR / "semantic_test_results.csv"),
        ("gnn_only", settings.ARTIFACTS_DIR / "gnn_test_results.csv"),
        ("hybrid_fusion", settings.ARTIFACTS_DIR / "hybrid_test_results.csv"),
    ]:
        if path.exists():
            df = pd.read_csv(path)
            df.insert(0, "model", name)
            rows.append(df)

    if not rows:
        logger.warning("No result files found -- run the training scripts first.")
        return

    combined = pd.concat(rows, ignore_index=True, sort=False)
    out_path = settings.ARTIFACTS_DIR / "ablation_comparison.csv"
    combined.to_csv(out_path, index=False)
    logger.info("\n%s", combined.to_string(index=False))
    logger.info("Wrote consolidated comparison to %s", out_path)


if __name__ == "__main__":
    main()
