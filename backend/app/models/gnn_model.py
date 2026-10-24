"""
Structural branch: a small Graph Convolutional Network over the
infrastructure graph (domain / IP / ASN / registrar / nameserver /
TLS cert nodes).

Implemented as plain PyTorch message passing rather than depending
on torch-geometric, since PyG's wheels need a package index that
isn't always reachable from restricted / offline training
environments (e.g. university lab machines behind a firewall). The
math is the same as a standard GCN layer:

    H' = sigma( D^-1/2 * A_hat * D^-1/2 * H * W )

Swap-in note: if torch-geometric is available in your environment,
you can replace `GCNLayer`/`GraphEncoder` with `torch_geometric.nn.GCNConv`
one-for-one -- the rest of the pipeline only depends on `GraphEncoder`
producing a fixed-size graph embedding.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F


def normalized_adjacency(edge_index: list[list[int]], num_nodes: int) -> torch.Tensor:
    """Builds D^-1/2 (A + I) D^-1/2 as a dense tensor. Fine for the small
    per-investigation graphs (a few dozen nodes) this project produces."""
    A = torch.eye(num_nodes)
    if edge_index and len(edge_index[0]) > 0:
        src, dst = edge_index
        for s, d in zip(src, dst):
            A[s, d] = 1.0
    deg = A.sum(dim=1)
    deg_inv_sqrt = torch.pow(deg.clamp(min=1e-6), -0.5)
    D_inv_sqrt = torch.diag(deg_inv_sqrt)
    return D_inv_sqrt @ A @ D_inv_sqrt


class GCNLayer(nn.Module):
    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.linear = nn.Linear(in_dim, out_dim)

    def forward(self, x: torch.Tensor, A_norm: torch.Tensor) -> torch.Tensor:
        return F.relu(self.linear(A_norm @ x))


class GraphEncoder(nn.Module):
    """Two-layer GCN + mean-pool readout -> fixed-size graph embedding."""

    def __init__(self, in_dim: int, hidden_dim: int = 32, out_dim: int = 32):
        super().__init__()
        self.gc1 = GCNLayer(in_dim, hidden_dim)
        self.gc2 = GCNLayer(hidden_dim, out_dim)
        self.proj = nn.Linear(out_dim, out_dim)

    def forward(self, node_features: torch.Tensor, edge_index: list[list[int]]) -> torch.Tensor:
        """node_features: (num_nodes, in_dim). Returns (out_dim,) graph embedding."""
        num_nodes = node_features.size(0)
        A_norm = normalized_adjacency(edge_index, num_nodes)
        h = self.gc1(node_features, A_norm)
        h = self.gc2(h, A_norm)
        pooled = h.mean(dim=0)
        return torch.tanh(self.proj(pooled))


def embed_graph(node_features: list[list[float]], edge_index: list[list[int]], model: "GraphEncoder") -> list[float]:
    if not node_features:
        return [0.0] * model.proj.out_features
    x = torch.tensor(node_features, dtype=torch.float32)
    model.eval()
    with torch.no_grad():
        emb = model(x, edge_index)
    return emb.tolist()
