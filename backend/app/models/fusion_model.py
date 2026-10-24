"""
Adaptive fusion layer: learns per-sample weights (alpha, beta) for
the semantic (Transformer) and structural (GNN) embeddings instead
of a fixed concatenation, so the model can lean on whichever signal
is more informative for a given URL (e.g. a brand-new domain with no
graph history should lean semantic; a domain reusing known-bad
infrastructure should lean structural).

    gate = softmax(MLP([semantic_emb ; graph_emb]))   # (alpha, beta)
    fused = alpha * semantic_emb_proj + beta * graph_emb_proj
"""
import torch
import torch.nn as nn


class AdaptiveFusion(nn.Module):
    def __init__(self, semantic_dim: int = 64, graph_dim: int = 32, fused_dim: int = 64):
        super().__init__()
        self.semantic_proj = nn.Linear(semantic_dim, fused_dim)
        self.graph_proj = nn.Linear(graph_dim, fused_dim)
        self.gate = nn.Sequential(
            nn.Linear(semantic_dim + graph_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 2),
        )

    def forward(self, semantic_emb: torch.Tensor, graph_emb: torch.Tensor):
        """Both inputs: (batch, dim). Returns (fused, (alpha, beta))."""
        gate_logits = self.gate(torch.cat([semantic_emb, graph_emb], dim=-1))
        weights = torch.softmax(gate_logits, dim=-1)
        alpha, beta = weights[:, 0:1], weights[:, 1:2]

        sem_p = torch.tanh(self.semantic_proj(semantic_emb))
        graph_p = torch.tanh(self.graph_proj(graph_emb))

        fused = alpha * sem_p + beta * graph_p
        return fused, (alpha.squeeze(-1), beta.squeeze(-1))


class PhishingClassifier(nn.Module):
    """Final head on top of the fused embedding -> phishing probability."""

    def __init__(self, fused_dim: int = 64, aux_dim: int = 25):
        super().__init__()
        # aux_dim = hand-crafted URL features, concatenated in for a
        # bit of extra precision beyond what the two branches alone give.
        self.net = nn.Sequential(
            nn.Linear(fused_dim + aux_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 1),
        )

    def forward(self, fused: torch.Tensor, aux_features: torch.Tensor) -> torch.Tensor:
        x = torch.cat([fused, aux_features], dim=-1)
        return torch.sigmoid(self.net(x)).squeeze(-1)


class HybridPhishingModel(nn.Module):
    """End-to-end wrapper: semantic branch + graph branch -> fusion -> classifier.

    Kept as a single module so training/evaluate.py can checkpoint one
    state_dict; the encoders themselves live in semantic_model.py /
    gnn_model.py and are passed in so they can also be trained/evaluated
    standalone for the ablation study (Transformer-only vs GNN-only vs hybrid).
    """

    def __init__(self, semantic_encoder, graph_encoder, semantic_dim=64, graph_dim=32, aux_dim=25):
        super().__init__()
        self.semantic_encoder = semantic_encoder
        self.graph_encoder = graph_encoder
        self.fusion = AdaptiveFusion(semantic_dim, graph_dim, fused_dim=64)
        self.classifier = PhishingClassifier(fused_dim=64, aux_dim=aux_dim)

    def forward(self, token_ids, node_features_batch, edge_index_batch, aux_features):
        semantic_emb = self.semantic_encoder(token_ids)  # (batch, semantic_dim)
        graph_embs = []
        for nf, ei in zip(node_features_batch, edge_index_batch):
            graph_embs.append(self.graph_encoder(nf, ei))
        graph_emb = torch.stack(graph_embs, dim=0)  # (batch, graph_dim)

        fused, (alpha, beta) = self.fusion(semantic_emb, graph_emb)
        prob = self.classifier(fused, aux_features)
        return prob, alpha, beta
