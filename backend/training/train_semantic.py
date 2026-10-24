"""
Phase 2: train the semantic Transformer encoder + a small classifier
head standalone, on tokenized URL text. Used both as its own
reported baseline (Transformer-only) and, once trained, its weights
are reused (frozen or fine-tuned) inside the hybrid fusion model in
train_hybrid.py.

Usage:
    python -m training.train_semantic
"""
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from app.config import settings
from app.features.text_features import url_to_tokens
from app.models.semantic_model import SemanticEncoder, Vocab, tokens_to_tensor
from datasets.brand_imbalance import brand_sample_weight

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.train_semantic")

PROCESSED = Path("datasets/processed")
MAX_LEN = 33


class UrlTextDataset(Dataset):
    def __init__(self, df: pd.DataFrame, vocab: Vocab, build_vocab: bool = False, weighted: bool = False):
        self.samples = []
        for _, row in df.iterrows():
            tokens = url_to_tokens(row["url"], max_tokens=MAX_LEN - 1)
            if build_vocab:
                for t in tokens:
                    vocab.add(t)
            weight = 1.0
            if weighted:
                host = urlparse(row["url"] if "://" in str(row["url"]) else "http://" + str(row["url"])).hostname or ""
                weight = brand_sample_weight(host, int(row["label"]))
            self.samples.append((tokens, int(row["label"]), weight))
        self.vocab = vocab

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        tokens, label, weight = self.samples[idx]
        ids = tokens_to_tensor(tokens, self.vocab, max_len=MAX_LEN)
        return ids, torch.tensor(label, dtype=torch.float32), torch.tensor(weight, dtype=torch.float32)


class SemanticClassifier(nn.Module):
    def __init__(self, encoder: SemanticEncoder):
        super().__init__()
        self.encoder = encoder
        self.head = nn.Linear(encoder.dim, 1)

    def forward(self, ids):
        emb = self.encoder(ids)
        return torch.sigmoid(self.head(emb)).squeeze(-1)


def main(epochs: int = 8, batch_size: int = 32, lr: float = 1e-3, data_tag: str = "_nn"):
    def _read(name: str) -> pd.DataFrame:
        tagged = PROCESSED / f"{name}{data_tag}.csv"
        if tagged.exists():
            return pd.read_csv(tagged)
        fallback = PROCESSED / f"{name}.csv"
        logger.warning("%s not found -- falling back to %s (run `datasets.preprocess --sample-size N --file-tag %s --with-brand-correction` for the intended smaller, brand-corrected split)",
                        tagged, fallback, data_tag)
        return pd.read_csv(fallback)

    train_df = _read("train")
    val_df = _read("val")
    test_df = _read("test")

    vocab = Vocab()
    train_ds = UrlTextDataset(train_df, vocab, build_vocab=True, weighted=True)
    val_ds = UrlTextDataset(val_df, vocab, build_vocab=False, weighted=False)
    test_ds = UrlTextDataset(test_df, vocab, build_vocab=False, weighted=False)
    logger.info("Vocab size: %d", len(vocab))
    n_upweighted = sum(1 for _, l, w in train_ds.samples if w > 1.0)
    logger.info("%d/%d training rows up-weighted for brand-representation correction (see datasets/brand_imbalance.py)",
                n_upweighted, len(train_ds))

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size)
    test_loader = DataLoader(test_ds, batch_size=batch_size)

    encoder = SemanticEncoder(vocab_size=len(vocab), max_len=MAX_LEN)
    model = SemanticClassifier(encoder)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCELoss(reduction="none")

    best_val_f1 = -1
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        for ids, labels, weights in train_loader:
            optimizer.zero_grad()
            preds = model(ids)
            loss = (criterion(preds, labels) * weights).mean()
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(labels)

        val_metrics = _evaluate(model, val_loader)
        logger.info("epoch %d loss=%.4f val_acc=%.4f val_f1=%.4f",
                    epoch + 1, total_loss / len(train_ds), val_metrics["accuracy"], val_metrics["f1"])

        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            torch.save(encoder.state_dict(), settings.SEMANTIC_MODEL_PATH)
            vocab.save(settings.SEMANTIC_VOCAB_PATH)

    # reload best checkpoint for final test evaluation
    encoder.load_state_dict(torch.load(settings.SEMANTIC_MODEL_PATH))
    model.encoder = encoder
    test_metrics = _evaluate(model, test_loader)
    logger.info("TEST (semantic-only): %s", test_metrics)
    pd.DataFrame([test_metrics]).to_csv(settings.ARTIFACTS_DIR / "semantic_test_results.csv", index=False)


def _evaluate(model, loader) -> dict:
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for ids, labels, _weights in loader:
            probs = model(ids)
            all_preds.extend(probs.tolist())
            all_labels.extend(labels.tolist())
    binary = [1 if p >= 0.5 else 0 for p in all_preds]
    metrics = {
        "accuracy": round(accuracy_score(all_labels, binary), 4),
        "f1": round(f1_score(all_labels, binary, zero_division=0), 4),
    }
    try:
        metrics["roc_auc"] = round(roc_auc_score(all_labels, all_preds), 4)
    except ValueError:
        metrics["roc_auc"] = None
    return metrics


if __name__ == "__main__":
    main()
