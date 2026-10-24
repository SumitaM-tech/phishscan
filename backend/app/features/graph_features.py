"""
Converts an infrastructure graph (domain -> IP -> ASN -> registrar ->
nameserver -> TLS cert) into a fixed-width node feature matrix and
edge index list consumable by the GNN encoder.

Node type is one-hot encoded and concatenated with a few structural
scalars (degree, whether it's the investigated target, a coarse risk
flag from known-bad indicator lists). This keeps the encoder cheap
and dependency-free while still giving the GNN real signal to learn
from ("URLs connected to this kind of infrastructure behave alike").
"""
from app.database import models

NODE_TYPES = ["DOMAIN", "IP", "ASN", "REGISTRAR", "NAMESERVER", "TLS CERTIFICATE"]


def node_type_onehot(node_type: str) -> list[float]:
    return [1.0 if node_type == t else 0.0 for t in NODE_TYPES]


def build_node_features(nodes: list[dict], edges: list[dict]) -> tuple[list[list[float]], dict]:
    """
    nodes: list of {"id", "type", "is_target", "risk"}
    edges: list of {"source", "target"}
    Returns (feature_matrix, id_to_index)
    """
    id_to_index = {n["id"]: i for i, n in enumerate(nodes)}
    degree = {n["id"]: 0 for n in nodes}
    for e in edges:
        if e["source"] in degree:
            degree[e["source"]] += 1
        if e["target"] in degree:
            degree[e["target"]] += 1

    risk_weight = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.0, None: 0.0}

    matrix = []
    for n in nodes:
        onehot = node_type_onehot(n["type"])
        scalar = [
            float(degree.get(n["id"], 0)),
            1.0 if n.get("is_target") else 0.0,
            risk_weight.get(n.get("risk"), 0.0),
        ]
        matrix.append(onehot + scalar)
    return matrix, id_to_index


def build_edge_index(edges: list[dict], id_to_index: dict) -> list[list[int]]:
    """Returns edge_index as [[src_idx,...], [dst_idx,...]] (bidirectional)."""
    src, dst = [], []
    for e in edges:
        if e["source"] in id_to_index and e["target"] in id_to_index:
            s, t = id_to_index[e["source"]], id_to_index[e["target"]]
            src += [s, t]
            dst += [t, s]
    return [src, dst]
