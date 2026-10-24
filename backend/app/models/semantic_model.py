"""
Semantic branch: a small Transformer encoder trained from scratch on
tokenized URL text (see app/features/text_features.py).

We deliberately do NOT pull a pretrained BERT/DistilBERT checkpoint:
those require large downloads and this project's scope (URL strings,
not natural-language documents) doesn't need transfer learning from
general-domain text. A compact from-scratch encoder trains fast on a
laptop GPU/CPU and is architecturally the same idea the proposal
describes ("Transformer -> semantic embedding").

Swap-in note: if you do want DistilBERT-style transfer learning,
replace `SemanticEncoder` with a `sentence-transformers` wrapper --
the rest of the pipeline (fusion, classifier) is agnostic to how the
embedding was produced, it just expects a fixed-size vector.
"""
import json
import math
import torch
import torch.nn as nn

from app.features.text_features import url_to_tokens

PAD, UNK, CLS = "<pad>", "<unk>", "<cls>"


class Vocab:
    def __init__(self, tokens: list[str] | None = None):
        self.token_to_id = {PAD: 0, UNK: 1, CLS: 2}
        if tokens:
            for t in tokens:
                self.add(t)

    def add(self, token: str) -> int:
        if token not in self.token_to_id:
            self.token_to_id[token] = len(self.token_to_id)
        return self.token_to_id[token]

    def encode(self, tokens: list[str]) -> list[int]:
        return [self.token_to_id.get(t, self.token_to_id[UNK]) for t in tokens]

    def __len__(self):
        return len(self.token_to_id)

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.token_to_id, f)

    @classmethod
    def load(cls, path):
        v = cls()
        with open(path) as f:
            v.token_to_id = json.load(f)
        return v


class PositionalEncoding(nn.Module):
    def __init__(self, dim: int, max_len: int = 64):
        super().__init__()
        pe = torch.zeros(max_len, dim)
        position = torch.arange(0, max_len).unsqueeze(1).float()
        div_term = torch.exp(torch.arange(0, dim, 2).float() * (-math.log(10000.0) / dim))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x):
        return x + self.pe[:, : x.size(1)]


class SemanticEncoder(nn.Module):
    """Small Transformer encoder producing one embedding per URL."""

    def __init__(self, vocab_size: int, dim: int = 64, heads: int = 4, layers: int = 2, max_len: int = 33):
        super().__init__()
        self.dim = dim
        self.embed = nn.Embedding(vocab_size, dim, padding_idx=0)
        self.pos = PositionalEncoding(dim, max_len=max_len)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=dim, nhead=heads, dim_feedforward=dim * 2, dropout=0.1, batch_first=True
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=layers)
        self.proj = nn.Linear(dim, dim)

    def forward(self, token_ids: torch.Tensor) -> torch.Tensor:
        """token_ids: (batch, seq_len) with CLS at position 0. Returns (batch, dim)."""
        mask = token_ids.eq(0)
        x = self.embed(token_ids)
        x = self.pos(x)
        x = self.encoder(x, src_key_padding_mask=mask)
        cls_out = x[:, 0, :]  # CLS token pooled representation
        return torch.tanh(self.proj(cls_out))


def tokens_to_tensor(tokens: list[str], vocab: Vocab, max_len: int = 33) -> torch.Tensor:
    ids = [vocab.token_to_id[CLS]] + vocab.encode(tokens)
    ids = ids[:max_len]
    ids += [0] * (max_len - len(ids))
    return torch.tensor(ids, dtype=torch.long)


def embed_url(url: str, model: "SemanticEncoder", vocab: Vocab, max_len: int = 33) -> list[float]:
    tokens = url_to_tokens(url, max_tokens=max_len - 1)
    ids = tokens_to_tensor(tokens, vocab, max_len=max_len).unsqueeze(0)
    model.eval()
    with torch.no_grad():
        emb = model(ids)
    return emb.squeeze(0).tolist()
