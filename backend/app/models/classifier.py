"""
Unified inference entrypoint used by the live API.

Loads whatever artifacts exist on disk (baselines always; hybrid
model only if training/train_hybrid.py has been run) and exposes a
single `score_url()` used by the investigation orchestrator. This
keeps `app/services/*` free of any ML-framework-specific code.
"""
import json
import pickle
import logging
from pathlib import Path

import numpy as np
import torch

from app.config import settings
from app.features.url_features import feature_vector, FEATURE_NAMES
from app.features.synthetic_features import synthetic_feature_vector
from app.features.text_features import url_to_tokens
from app.models.semantic_model import SemanticEncoder, Vocab, tokens_to_tensor
from app.models.gnn_model import GraphEncoder
from app.models.fusion_model import AdaptiveFusion, PhishingClassifier
from app.features.graph_features import build_node_features, build_edge_index

logger = logging.getLogger("phishscan.classifier")


class PhishScanModel:
    """SCORING SOURCES, in priority order:

      1. PRIMARY  -- RF / XGBoost / SVM trained on the SYNTHETIC URL
         dataset (artifacts/synthetic/, extended feature set in
         app/features/synthetic_features.py; see training/train_synthetic.py).
      2. BACKUP   -- the original RF / XGBoost / SVM trained on the real
         datasets (artifacts/*.pkl, 20 host-only features). Used
         automatically if the synthetic artifacts are missing, fail to
         load, raise at inference time, or USE_SYNTHETIC_MODELS=false.
      3. HEURISTIC -- the transparent rule-based score, if no trained
         artifacts exist at all.

    Lazily loads artifacts on first use; falls back to a rule-based
    heuristic score (still fully functional, just less accurate) when
    no trained artifacts are present -- e.g. right after a fresh clone
    before `training/` has been run.

    Hybrid (Transformer+GNN+fusion) scoring is currently DISABLED: a
    joint fine-tuning run (training/train_hybrid.py) on the brand-
    corrected sample collapsed to predicting "legitimate" for almost
    everything (val F1 stuck at ~0 across 5 epochs) and, worse, was
    about to overwrite the working standalone semantic checkpoint on
    every "improvement" from an initial best-F1 of -1. Killed before
    that finished; artifacts/fusion_model.pt and gnn_model.pt were
    moved to artifacts/disabled_broken_20260924/ rather than shipped.
    `_load_fusion_head`/`_load_graph_encoder` finding nothing there is
    what makes `has_trained_hybrid` False and routes scoring through
    baselines only -- verified this actually fixes real cases (see
    README): netflix.com dropped from a wrongly-flagged 46.3/100
    "suspicious" to a correctly-clean 17.2/100 once the broken hybrid
    signal stopped being blended in. Re-enabling the hybrid path needs
    the joint fine-tuner's instability fixed first (more data, lower
    LR, gradient clipping, and a saved-checkpoint floor above F1=0 are
    the likely culprits) -- don't just drop new checkpoints back into
    artifacts/ without re-verifying the same way.
    """

    def __init__(self):
        self._rf = self._load_pickle(settings.RF_MODEL_PATH)
        self._xgb = self._load_pickle(settings.XGB_MODEL_PATH)
        self._svm = self._load_pickle(settings.SVM_MODEL_PATH)
        self._scaler = self._load_pickle(settings.ARTIFACTS_DIR / "scaler.pkl")

        self._syn_rf = self._syn_xgb = self._syn_svm = self._syn_scaler = None
        if settings.USE_SYNTHETIC_MODELS:
            d = settings.SYNTHETIC_ARTIFACTS_DIR
            try:
                self._syn_rf = self._load_pickle(d / "rf.pkl")
                self._syn_xgb = self._load_pickle(d / "xgboost.pkl")
                self._syn_svm = self._load_pickle(d / "svm.pkl")
                self._syn_scaler = self._load_pickle(d / "scaler.pkl")
            except Exception:  # noqa: BLE001 -- a corrupt/incompatible synthetic artifact must never take the API down
                logger.exception("Could not load synthetic models; using the original backup models")
                self._syn_rf = self._syn_xgb = self._syn_svm = self._syn_scaler = None
        self._syn_threshold = self._load_syn_threshold()

        self._semantic, self._vocab = self._load_semantic()
        self._graph_encoder = self._load_graph_encoder()
        self._fusion, self._head = self._load_fusion_head()

    # ---- loading -------------------------------------------------------
    @staticmethod
    def _load_pickle(path: Path):
        if path.exists():
            with open(path, "rb") as f:
                return pickle.load(f)
        return None

    def _load_semantic(self):
        if settings.SEMANTIC_MODEL_PATH.exists() and settings.SEMANTIC_VOCAB_PATH.exists():
            vocab = Vocab.load(settings.SEMANTIC_VOCAB_PATH)
            model = SemanticEncoder(vocab_size=len(vocab))
            model.load_state_dict(torch.load(settings.SEMANTIC_MODEL_PATH, map_location="cpu"))
            model.eval()
            return model, vocab
        return None, None

    def _load_graph_encoder(self):
        if settings.GNN_MODEL_PATH.exists():
            model = GraphEncoder(in_dim=9)
            model.load_state_dict(torch.load(settings.GNN_MODEL_PATH, map_location="cpu"))
            model.eval()
            return model
        return GraphEncoder(in_dim=9)  # untrained fallback, still runs

    def _load_fusion_head(self):
        if settings.FUSION_MODEL_PATH.exists():
            ckpt = torch.load(settings.FUSION_MODEL_PATH, map_location="cpu")
            fusion = AdaptiveFusion()
            head = PhishingClassifier(aux_dim=len(FEATURE_NAMES))
            fusion.load_state_dict(ckpt["fusion"])
            head.load_state_dict(ckpt["classifier"])
            fusion.eval()
            head.eval()
            return fusion, head
        return None, None

    @staticmethod
    def _load_syn_threshold():
        meta = settings.SYNTHETIC_ARTIFACTS_DIR / "model_metadata.json"
        try:
            return float(json.loads(meta.read_text()).get("ensemble_threshold"))
        except Exception:  # noqa: BLE001
            return None

    @property
    def has_synthetic_models(self) -> bool:
        return any([self._syn_rf, self._syn_xgb, self._syn_svm])

    @property
    def has_trained_baselines(self) -> bool:
        """True if ANY trained URL classifier is available (synthetic
        primary or original backup)."""
        return self.has_synthetic_models or any([self._rf, self._xgb, self._svm])

    @property
    def has_backup_models(self) -> bool:
        return any([self._rf, self._xgb, self._svm])

    @property
    def active_source(self) -> str:
        if self.has_synthetic_models:
            return "synthetic"
        if self.has_backup_models:
            return "original_backup"
        return "heuristic"

    @property
    def has_trained_hybrid(self) -> bool:
        return self._semantic is not None and self._fusion is not None

    # ---- inference -------------------------------------------------------
    def score_url(self, url: str, graph_nodes: list[dict], graph_edges: list[dict]) -> dict:
        vec, names = feature_vector(url)  # original 20 host features (backup models + hybrid aux)
        x = np.array(vec, dtype=float).reshape(1, -1)

        # --- PRIMARY: synthetic-trained models --------------------------
        source = "heuristic"
        baseline_scores = {"random_forest": None, "xgboost": None, "svm": None}
        feature_map = dict(zip(names, vec))
        if self.has_synthetic_models:
            try:
                syn_vec, syn_names = synthetic_feature_vector(url)
                baseline_scores = self._synthetic_scores(np.array(syn_vec, dtype=float).reshape(1, -1))
                feature_map = dict(zip(syn_names, syn_vec))
                source = "synthetic"
            except Exception:  # noqa: BLE001
                logger.exception("Synthetic scoring failed; falling back to the original models")
                baseline_scores = {"random_forest": None, "xgboost": None, "svm": None}

        # --- BACKUP: original real-data models ---------------------------
        if source != "synthetic" and self.has_backup_models:
            baseline_scores = self._baseline_scores(x)
            source = "original_backup"

        semantic_score, alpha_val = None, None
        graph_score, beta_val = None, None
        hybrid_score = None

        if self.has_trained_hybrid:
            hybrid_score, alpha_val, beta_val = self._hybrid_score(url, vec, graph_nodes, graph_edges)

        scores = [s for s in baseline_scores.values() if s is not None]
        if hybrid_score is not None:
            # Baselines get more trust than the neural hybrid score here.
            # Both were trained on the same real corpus, but the hybrid's
            # semantic (Transformer) branch reads raw URL text tokens,
            # where the same dataset bias documented in url_features.py
            # shows up again: legitimate training examples (PhiUSIIL) are
            # domain-only with no path, so words like "login"/"verify"
            # never appear in ANY legitimate training token stream, only
            # in phishing ones -- the Transformer over-learns "auth-page
            # vocabulary = phishing" the same way the old path features
            # did structurally. The baselines don't have this specific
            # failure mode after the feature fixes in url_features.py, so
            # they're weighted higher until real (non-fabricated)
            # legitimate deep-link training text is available to retrain
            # the semantic branch properly.
            final_score = 0.35 * hybrid_score + 0.65 * (np.mean(scores) if scores else hybrid_score)
        elif scores:
            final_score = float(np.mean(scores))
        else:
            final_score = self._heuristic_score(vec, names)

        final_score = float(np.clip(final_score, 0.0, 1.0))
        verdict = self._verdict(final_score)

        if hybrid_score is not None:
            mode = "hybrid"
        elif source == "synthetic":
            mode = "synthetic"
        elif source == "original_backup":
            mode = "baseline"
        else:
            mode = "heuristic"

        return {
            "score": round(final_score * 100, 1),
            "verdict": verdict,
            "confidence": round(0.5 + abs(final_score - 0.5), 3),
            "baseline_scores": baseline_scores,
            "hybrid_score": hybrid_score,
            "semantic_weight": alpha_val,
            "graph_weight": beta_val,
            "features": feature_map,
            "model_mode": mode,
            "model_source": source,
        }

    def _synthetic_scores(self, x: np.ndarray) -> dict:
        out = {"random_forest": None, "xgboost": None, "svm": None}
        if self._syn_rf is not None:
            out["random_forest"] = float(self._syn_rf.predict_proba(x)[0][1])
        if self._syn_xgb is not None:
            out["xgboost"] = float(self._syn_xgb.predict_proba(x)[0][1])
        if self._syn_svm is not None:
            xs = self._syn_scaler.transform(x) if self._syn_scaler is not None else x
            out["svm"] = float(self._syn_svm.predict_proba(xs)[0][1])
        return out

    def _baseline_scores(self, x: np.ndarray) -> dict:
        out = {"random_forest": None, "xgboost": None, "svm": None}
        x_scaled = self._scaler.transform(x) if self._scaler is not None else x
        if self._rf is not None:
            out["random_forest"] = float(self._rf.predict_proba(x)[0][1])
        if self._xgb is not None:
            out["xgboost"] = float(self._xgb.predict_proba(x)[0][1])
        if self._svm is not None:
            out["svm"] = float(self._svm.predict_proba(x_scaled)[0][1])
        return out

    def _hybrid_score(self, url, aux_vec, graph_nodes, graph_edges):
        tokens = url_to_tokens(url, max_tokens=32)
        ids = tokens_to_tensor(tokens, self._vocab).unsqueeze(0)

        node_feats, id_to_index = build_node_features(graph_nodes, graph_edges)
        edge_index = build_edge_index(graph_edges, id_to_index)
        if not node_feats:
            node_feats = [[0.0] * 9]

        with torch.no_grad():
            semantic_emb = self._semantic(ids)
            graph_x = torch.tensor(node_feats, dtype=torch.float32)
            graph_emb = self._graph_encoder(graph_x, edge_index).unsqueeze(0)
            fused, (alpha, beta) = self._fusion(semantic_emb, graph_emb)
            aux = torch.tensor([aux_vec], dtype=torch.float32)
            prob = self._head(fused, aux)

        return float(prob.item()), float(alpha.item()), float(beta.item())

    @staticmethod
    def _heuristic_score(vec: list[float], names: list[str]) -> float:
        """Transparent rule-based fallback used only when no artifacts
        are trained yet, so the API is usable immediately after clone."""
        feats = dict(zip(names, vec))
        score = 0.05
        score += 0.12 * min(feats.get("suspicious_word_count", 0), 3)
        score += 0.10 * min(feats.get("brand_token_count", 0), 2)
        score += 0.15 if feats.get("has_ip_host") else 0
        score += 0.10 if not feats.get("has_https") else 0
        score += 0.08 if feats.get("is_shortened") else 0
        score += 0.08 if feats.get("hyphen_in_host") else 0
        score += 0.05 if feats.get("subdomain_count", 0) >= 3 else 0
        score += 0.10 if feats.get("punycode") else 0
        score += 0.05 if feats.get("long_host") else 0
        return min(score, 0.97)

    @staticmethod
    def _verdict(score: float) -> str:
        if score >= 0.75:
            return "malicious"
        if score >= 0.45:
            return "suspicious"
        if score >= 0.0:
            return "clean"
        return "unknown"


_model_singleton: PhishScanModel | None = None


def get_model() -> PhishScanModel:
    global _model_singleton
    if _model_singleton is None:
        _model_singleton = PhishScanModel()
    return _model_singleton
