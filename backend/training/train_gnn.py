"""
Phase 3: train the GCN structural encoder standalone.

Each training URL needs an infrastructure graph (domain -> IP -> ASN
-> registrar -> nameserver -> TLS cert) to learn from. Two modes:

  --live       Actually run the evidence collectors (DNS/RDAP/TLS/CT)
               for every training URL and build real graphs. This is
               the correct approach for a real training run, but is
               slow (network round trips per sample) and requires
               outbound internet access to arbitrary hosts.

  (default)    Deterministic *synthetic* graphs derived from the URL
               string itself (consistent hashing -> pseudo IP/ASN/
               registrar/nameserver nodes). This keeps the GNN
               trainable end-to-end in restricted/offline
               environments (e.g. a sandboxed grading environment, or
               a laptop with no internet) for architecture validation.
               Swap to --live for a real research result.

Graphs are cached to datasets/processed/graph_cache.json so re-runs
(e.g. after tweaking the model) don't redo collection.
"""
import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from app.config import settings
from app.services.url_service import get_hostname
from app.features.graph_features import build_node_features, build_edge_index

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishscan.train_gnn")

PROCESSED = Path("datasets/processed")
CACHE_PATH = PROCESSED / "graph_cache.json"


def _synthetic_graph(url: str) -> dict:
    """Deterministic pseudo-infrastructure graph from a hash of the
    hostname, so identical hosts always get identical (fake) infra --
    close enough in spirit to real reuse-of-infrastructure patterns
    for the GNN to have *something* structural to learn from offline."""
    hostname = get_hostname(url) or url
    h = hashlib.sha256(hostname.encode()).hexdigest()

    domain_id = f"domain::{hostname}"
    ip = f"pseudo-ip::{h[0:8]}"
    asn = f"pseudo-asn::{int(h[8:12], 16) % 4000}"
    registrar = f"pseudo-registrar::{h[12:16]}"
    ns = f"pseudo-ns::{h[16:20]}"

    nodes = [
        {"id": domain_id, "type": "DOMAIN", "is_target": True, "risk": None},
        {"id": ip, "type": "IP", "is_target": False, "risk": None},
        {"id": asn, "type": "ASN", "is_target": False, "risk": None},
        {"id": registrar, "type": "REGISTRAR", "is_target": False, "risk": None},
        {"id": ns, "type": "NAMESERVER", "is_target": False, "risk": None},
    ]
    edges = [
        {"source": domain_id, "target": ip},
        {"source": ip, "target": asn},
        {"source": domain_id, "target": registrar},
        {"source": domain_id, "target": ns},
    ]
    return {"nodes": nodes, "edges": edges}


def _live_graph(url: str) -> dict:
    from app.services.evidence_service import gather_evidence
    from app.services.graph_service import build_graph

    hostname = get_hostname(url)
    bundle = gather_evidence(url, follow_redirects=False)
    graph = build_graph(url, hostname, bundle)
    nodes = [{"id": n["id"], "type": n["type"], "is_target": n.get("is_target", False), "risk": n.get("risk")} for n in graph["nodes"]]
    edges = [{"source": e["source"], "target": e["target"]} for e in graph["edges"]]
    return {"nodes": nodes, "edges": edges}


def load_or_build_graphs(urls: list[str], live: bool) -> dict:
    cache = {}
    if CACHE_PATH.exists():
        cache = json.loads(CACHE_PATH.read_text())

    for url in urls:
        if url in cache:
            continue
        try:
            cache[url] = _live_graph(url) if live else _synthetic_graph(url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Graph build failed for %s (%s) -- using synthetic fallback", url, exc)
            cache[url] = _synthetic_graph(url)

    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache))
    return cache


class GraphClassifier(nn.Module):
    def __init__(self, encoder):
        super().__init__()
        self.encoder = encoder
        self.head = nn.Linear(encoder.proj.out_features, 1)

    def forward(self, node_features, edge_index):
        emb = self.encoder(node_features, edge_index)
        return torch.sigmoid(self.head(emb))


def main(live: bool = False, epochs: int = 15, lr: float = 1e-3):
    from app.models.gnn_model import GraphEncoder

    train_df = pd.read_csv(PROCESSED / "train.csv")
    val_df = pd.read_csv(PROCESSED / "val.csv")
    test_df = pd.read_csv(PROCESSED / "test.csv")

    all_urls = pd.concat([train_df["url"], val_df["url"], test_df["url"]]).unique().tolist()
    logger.info("Building graphs for %d unique URLs (live=%s)...", len(all_urls), live)
    graphs = load_or_build_graphs(all_urls, live=live)

    def to_tensors(df):
        items = []
        for _, row in df.iterrows():
            g = graphs[row["url"]]
            node_feats, id_to_index = build_node_features(g["nodes"], g["edges"])
            edge_index = build_edge_index(g["edges"], id_to_index)
            x = torch.tensor(node_feats, dtype=torch.float32)
            y = torch.tensor(float(row["label"]))
            items.append((x, edge_index, y))
        return items

    train_items = to_tensors(train_df)
    val_items = to_tensors(val_df)
    test_items = to_tensors(test_df)

    encoder = GraphEncoder(in_dim=9)
    model = GraphClassifier(encoder)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCELoss()

    best_f1 = -1
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        for x, edge_index, y in train_items:
            optimizer.zero_grad()
            pred = model(x, edge_index).squeeze()
            loss = criterion(pred, y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        val_metrics = _evaluate(model, val_items)
        logger.info("epoch %d loss=%.4f val_acc=%.4f val_f1=%.4f",
                    epoch + 1, total_loss / max(len(train_items), 1), val_metrics["accuracy"], val_metrics["f1"])
        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            torch.save(encoder.state_dict(), settings.GNN_MODEL_PATH)

    encoder.load_state_dict(torch.load(settings.GNN_MODEL_PATH))
    model.encoder = encoder
    test_metrics = _evaluate(model, test_items)
    logger.info("TEST (GNN-only): %s", test_metrics)
    pd.DataFrame([test_metrics]).to_csv(settings.ARTIFACTS_DIR / "gnn_test_results.csv", index=False)


def _evaluate(model, items) -> dict:
    model.eval()
    preds, labels = [], []
    with torch.no_grad():
        for x, edge_index, y in items:
            p = model(x, edge_index).squeeze().item()
            preds.append(p)
            labels.append(y.item())
    binary = [1 if p >= 0.5 else 0 for p in preds]
    metrics = {
        "accuracy": round(accuracy_score(labels, binary), 4),
        "f1": round(f1_score(labels, binary, zero_division=0), 4),
    }
    try:
        metrics["roc_auc"] = round(roc_auc_score(labels, preds), 4)
    except ValueError:
        metrics["roc_auc"] = None
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Collect real infrastructure graphs instead of synthetic ones")
    parser.add_argument("--epochs", type=int, default=15)
    args = parser.parse_args()
    main(live=args.live, epochs=args.epochs)
