"""
Phase 4: train the full hybrid model -- semantic + structural
branches combined through the adaptive fusion layer, plus the
hand-crafted URL features as auxiliary input to the final classifier
head. This is the core contribution of the project.

Loads the (optionally pretrained) semantic encoder and GNN encoder
from Phase 2/3 as a warm start, then fine-tunes everything jointly.

Usage:
    python -m training.train_hybrid
"""
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from app.config import settings
from app.features.url_features import FEATURE_NAMES
from app.features.text_features import url_to_tokens
from app.features.graph_features import build_node_features, build_edge_index
from app.models.semantic_model import SemanticEncoder, Vocab, tokens_to_tensor
from app.models.gnn_model import GraphEncoder
from app.models.fusion_model import AdaptiveFusion, PhishingClassifier
from training.train_gnn import load_or_build_graphs
from datasets.brand_imbalance import brand_sample_weight

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.train_hybrid")

PROCESSED = Path("datasets/processed")
MAX_LEN = 33


def _read(name: str, data_tag: str) -> pd.DataFrame:
    tagged = PROCESSED / f"{name}{data_tag}.csv"
    if tagged.exists():
        return pd.read_csv(tagged)
    fallback = PROCESSED / f"{name}.csv"
    logger.warning("%s not found -- falling back to %s", tagged, fallback)
    return pd.read_csv(fallback)


def _load_vocab() -> Vocab:
    if settings.SEMANTIC_VOCAB_PATH.exists():
        return Vocab.load(settings.SEMANTIC_VOCAB_PATH)
    logger.warning("No pretrained vocab found -- run training.train_semantic first for a warm start. Building a fresh vocab instead.")
    vocab = Vocab()
    for split in ("train", "val", "test"):
        df = pd.read_csv(PROCESSED / f"{split}.csv")
        for url in df["url"]:
            for t in url_to_tokens(url, max_tokens=MAX_LEN - 1):
                vocab.add(t)
    return vocab


def _prep_split(df: pd.DataFrame, vocab: Vocab, graphs: dict):
    items = []
    for _, row in df.iterrows():
        tokens = url_to_tokens(row["url"], max_tokens=MAX_LEN - 1)
        ids = tokens_to_tensor(tokens, vocab, max_len=MAX_LEN)

        g = graphs[row["url"]]
        node_feats, id_to_index = build_node_features(g["nodes"], g["edges"])
        edge_index = build_edge_index(g["edges"], id_to_index)
        x = torch.tensor(node_feats, dtype=torch.float32)

        aux = torch.tensor(row[FEATURE_NAMES].values.astype(float), dtype=torch.float32)
        y = torch.tensor(float(row["label"]))
        host = urlparse(row["url"] if "://" in str(row["url"]) else "http://" + str(row["url"])).hostname or ""
        weight = torch.tensor(brand_sample_weight(host, int(row["label"])))
        items.append((ids, x, edge_index, aux, y, weight))
    return items


def main(epochs: int = 6, lr: float = 5e-4, live_graphs: bool = False, data_tag: str = "_nn"):
    train_df = _read("train", data_tag)
    val_df = _read("val", data_tag)
    test_df = _read("test", data_tag)

    vocab = _load_vocab()
    all_urls = pd.concat([train_df["url"], val_df["url"], test_df["url"]]).unique().tolist()
    graphs = load_or_build_graphs(all_urls, live=live_graphs)

    train_items = _prep_split(train_df, vocab, graphs)
    val_items = _prep_split(val_df, vocab, graphs)
    test_items = _prep_split(test_df, vocab, graphs)

    semantic_encoder = SemanticEncoder(vocab_size=len(vocab), max_len=MAX_LEN)
    if settings.SEMANTIC_MODEL_PATH.exists():
        semantic_encoder.load_state_dict(torch.load(settings.SEMANTIC_MODEL_PATH))
        logger.info("Warm-started semantic encoder from %s", settings.SEMANTIC_MODEL_PATH)

    graph_encoder = GraphEncoder(in_dim=9)
    if settings.GNN_MODEL_PATH.exists():
        graph_encoder.load_state_dict(torch.load(settings.GNN_MODEL_PATH))
        logger.info("Warm-started GNN encoder from %s", settings.GNN_MODEL_PATH)

    fusion = AdaptiveFusion(semantic_dim=semantic_encoder.dim, graph_dim=graph_encoder.proj.out_features)
    head = PhishingClassifier(fused_dim=64, aux_dim=len(FEATURE_NAMES))

    params = list(semantic_encoder.parameters()) + list(graph_encoder.parameters()) + \
        list(fusion.parameters()) + list(head.parameters())
    optimizer = torch.optim.Adam(params, lr=lr)
    criterion = nn.BCELoss(reduction="none")

    best_f1 = -1
    for epoch in range(epochs):
        semantic_encoder.train(); graph_encoder.train(); fusion.train(); head.train()
        total_loss = 0.0
        for ids, x, edge_index, aux, y, weight in train_items:
            optimizer.zero_grad()
            sem_emb = semantic_encoder(ids.unsqueeze(0))
            graph_emb = graph_encoder(x, edge_index).unsqueeze(0)
            fused, _ = fusion(sem_emb, graph_emb)
            pred = head(fused, aux.unsqueeze(0)).squeeze()
            loss = criterion(pred, y) * weight
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        val_metrics, _ = _evaluate(semantic_encoder, graph_encoder, fusion, head, val_items)
        logger.info("epoch %d loss=%.4f val_acc=%.4f val_f1=%.4f",
                    epoch + 1, total_loss / max(len(train_items), 1), val_metrics["accuracy"], val_metrics["f1"])

        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            torch.save(semantic_encoder.state_dict(), settings.SEMANTIC_MODEL_PATH)
            torch.save(graph_encoder.state_dict(), settings.GNN_MODEL_PATH)
            torch.save({"fusion": fusion.state_dict(), "classifier": head.state_dict()}, settings.FUSION_MODEL_PATH)
            vocab.save(settings.SEMANTIC_VOCAB_PATH)

    # reload best checkpoint
    semantic_encoder.load_state_dict(torch.load(settings.SEMANTIC_MODEL_PATH))
    graph_encoder.load_state_dict(torch.load(settings.GNN_MODEL_PATH))
    ckpt = torch.load(settings.FUSION_MODEL_PATH)
    fusion.load_state_dict(ckpt["fusion"])
    head.load_state_dict(ckpt["classifier"])

    test_metrics, avg_weights = _evaluate(semantic_encoder, graph_encoder, fusion, head, test_items)
    logger.info("TEST (hybrid): %s", test_metrics)
    logger.info("Average fusion weights -- semantic(alpha)=%.3f graph(beta)=%.3f", avg_weights[0], avg_weights[1])
    pd.DataFrame([test_metrics]).to_csv(settings.ARTIFACTS_DIR / "hybrid_test_results.csv", index=False)


def _evaluate(semantic_encoder, graph_encoder, fusion, head, items):
    semantic_encoder.eval(); graph_encoder.eval(); fusion.eval(); head.eval()
    preds, labels, alphas, betas = [], [], [], []
    with torch.no_grad():
        for ids, x, edge_index, aux, y, _weight in items:
            sem_emb = semantic_encoder(ids.unsqueeze(0))
            graph_emb = graph_encoder(x, edge_index).unsqueeze(0)
            fused, (a, b) = fusion(sem_emb, graph_emb)
            p = head(fused, aux.unsqueeze(0)).squeeze().item()
            preds.append(p)
            labels.append(y.item())
            alphas.append(a.item())
            betas.append(b.item())
    binary = [1 if p >= 0.5 else 0 for p in preds]
    metrics = {
        "accuracy": round(accuracy_score(labels, binary), 4),
        "f1": round(f1_score(labels, binary, zero_division=0), 4),
    }
    try:
        metrics["roc_auc"] = round(roc_auc_score(labels, preds), 4)
    except ValueError:
        metrics["roc_auc"] = None
    avg_weights = (sum(alphas) / max(len(alphas), 1), sum(betas) / max(len(betas), 1))
    return metrics, avg_weights


if __name__ == "__main__":
    main()
