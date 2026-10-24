"""
Detection tests for the synthetic-trained (primary) classifier and the
original-model backup path.

Run from backend/:
    python -m pytest tests -q          # if pytest is installed
    python tests/test_synthetic_detection.py   # plain script, no pytest needed
"""
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
warnings.filterwarnings("ignore")

from app.config import settings  # noqa: E402
from app.models.classifier import PhishScanModel  # noqa: E402
from app.services.url_service import normalize_url  # noqa: E402

PHISHING = [
    "http://paypal-secure-login-verify.tk/signin.php",
    "http://192.168.44.12:8080/paypal/login.php",
    "https://paypa1.com/login",
    "https://faceb00k-security.com/checkpoint",
    "https://secure.paypal.com.account-verify.xyz/webscr?cmd=_login",
    "https://xn--pypal-4ve.com/",
    "https://appleid.apple.com.verify-id.ml/",
    "amazon-gift-claim.top/login.php",
    "https://www.netflix.com/scM?ogin?nextpage=https%3A%2F%2Fwww.netflix.com%2Fbrowse",
    "https://www.amazon.com@evil-site.top/login",
    "https://wellsfargo-banking-service.co/",
    "http://download.chxxdlfz.su/update/zoom_document.rar",
]
LEGITIMATE = [
    "https://www.netflix.com/browse",
    "https://accounts.google.com/signin/v2/identifier",
    "https://www.paypal.com/signin",
    "https://slack.com/signin",
    "https://login.ox.ac.uk/",
    "https://www.microsoft.com/en-us/security",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://docs.python.org/3/library/urllib.html",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://dl.dropboxusercontent.com/s/abc123/report.pdf",
    "http://example-shop.com/products/shoes-123",
]


def _score(model, url):
    return model.score_url(normalize_url(url), [], [])


def test_synthetic_model_is_primary_and_detects():
    m = PhishScanModel()
    assert m.has_synthetic_models, "run `python -m training.train_synthetic` first"
    assert m.active_source == "synthetic"
    for u in PHISHING:
        r = _score(m, u)
        assert r["model_source"] == "synthetic" and r["score"] >= 45, (u, r["score"])
    for u in LEGITIMATE:
        r = _score(m, u)
        assert r["score"] < 45, (u, r["score"])


def test_backup_models_take_over_when_synthetic_unavailable():
    orig = settings.USE_SYNTHETIC_MODELS
    settings.USE_SYNTHETIC_MODELS = False
    try:
        m = PhishScanModel()
        assert not m.has_synthetic_models
        r = _score(m, "http://paypal-secure-login-verify.tk/signin.php")
        assert r["model_source"] == "original_backup" and r["model_mode"] == "baseline"
        assert r["baseline_scores"]["random_forest"] is not None
    finally:
        settings.USE_SYNTHETIC_MODELS = orig


def test_synthetic_dataset_is_present_and_domain_disjoint():
    import pandas as pd
    from datasets.synthetic_generator import _domain_group
    df = pd.read_csv(settings.SYNTHETIC_DATASET_PATH)
    assert set(df.label.unique()) == {0, 1} and set(df.split.unique()) == {"train", "val", "test"}
    df["g"] = df.url.map(_domain_group)
    per_group_splits = df.groupby("g").split.nunique()
    assert (per_group_splits == 1).all(), "a domain leaked across splits"


if __name__ == "__main__":
    test_synthetic_model_is_primary_and_detects()
    test_backup_models_take_over_when_synthetic_unavailable()
    test_synthetic_dataset_is_present_and_domain_disjoint()
    print("all synthetic detection tests passed")
