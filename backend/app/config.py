"""
Central configuration for PhishScan backend.
Reads from environment variables with sane local defaults so the
project runs out-of-the-box with SQLite, and can be pointed at
Postgres/Redis in production by just setting env vars. No dataset
paths, feed URLs, or credentials are hardcoded into application
logic -- everything below is env-overridable, and .env.example
documents every one of them.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def _bool(name: str, default: str) -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")

class Settings:
    APP_NAME: str = "PhishScan API"
    API_PREFIX: str = "/api"

    # Storage layer -----------------------------------------------------
    # Defaults to local SQLite so the app runs with zero setup; set
    # DATABASE_URL to a postgresql+psycopg2:// URL for the Postgres
    # deployment the architecture calls for (see docker-compose.yml,
    # which stands up a matching Postgres container).
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR}/phishscan.db"
    )
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # CORS ----------------------------------------------------------------
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

    # Evidence collection ---------------------------------------------------
    HTTP_TIMEOUT_SECONDS: float = float(os.getenv("HTTP_TIMEOUT_SECONDS", "6"))
    DNS_TIMEOUT_SECONDS: float = float(os.getenv("DNS_TIMEOUT_SECONDS", "4"))
    TLS_TIMEOUT_SECONDS: float = float(os.getenv("TLS_TIMEOUT_SECONDS", "4"))
    CT_LOOKUP_ENABLED: bool = _bool("CT_LOOKUP_ENABLED", "true")
    FOLLOW_REDIRECTS: bool = True

    # ML artifacts ------------------------------------------------------
    ARTIFACTS_DIR: Path = BASE_DIR / "artifacts"
    RF_MODEL_PATH: Path = ARTIFACTS_DIR / "rf.pkl"
    XGB_MODEL_PATH: Path = ARTIFACTS_DIR / "xgboost.pkl"
    SVM_MODEL_PATH: Path = ARTIFACTS_DIR / "svm.pkl"
    SEMANTIC_MODEL_PATH: Path = ARTIFACTS_DIR / "semantic_model.pt"
    SEMANTIC_VOCAB_PATH: Path = ARTIFACTS_DIR / "semantic_vocab.json"
    GNN_MODEL_PATH: Path = ARTIFACTS_DIR / "gnn_model.pt"
    FUSION_MODEL_PATH: Path = ARTIFACTS_DIR / "fusion_model.pt"

    # Synthetic-data models (PRIMARY scorer). The files above are the
    # original real-data models and act as the BACKUP scorer. Set
    # USE_SYNTHETIC_MODELS=false to force the original models only.
    USE_SYNTHETIC_MODELS: bool = _bool("USE_SYNTHETIC_MODELS", "true")
    SYNTHETIC_ARTIFACTS_DIR: Path = ARTIFACTS_DIR / "synthetic"
    SYNTHETIC_DATASET_PATH: Path = BASE_DIR / "datasets" / "synthetic" / "synthetic_urls.csv"

    # Historical / baseline dataset (Phase 1 training only) -----------------
    UCI_PHISHING_URL: str = os.getenv(
        "UCI_PHISHING_URL",
        "https://archive.ics.uci.edu/static/public/327/phishing+websites.zip",
    )

    # --- Real-time threat-intelligence feeds -----------------------------
    # PhishTank: official downloadable feed. An app_key is optional but
    # raises your rate limit -- get one at https://www.phishtank.com/api_register.php
    # and set it as an env var; it is never hardcoded here.
    PHISHTANK_APP_KEY: str = os.getenv("PHISHTANK_APP_KEY", "")
    PHISHTANK_FEED_URL: str = os.getenv(
        "PHISHTANK_FEED_URL", "https://data.phishtank.com/data/online-valid.csv"
    )
    PHISHTANK_SYNC_INTERVAL_MINUTES: int = int(os.getenv("PHISHTANK_SYNC_INTERVAL_MINUTES", "60"))

    # OpenPhish: community feed is the free default (12h-old data, no key
    # needed). Academic/commercial access swaps in a different feed URL
    # and API key issued to you -- both come from env vars, never code.
    OPENPHISH_FEED_URL: str = os.getenv("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
    OPENPHISH_API_KEY: str = os.getenv("OPENPHISH_API_KEY", "")
    OPENPHISH_SYNC_INTERVAL_MINUTES: int = int(os.getenv("OPENPHISH_SYNC_INTERVAL_MINUTES", "60"))

    # Scheduler: automatic background sync so no one has to manually
    # re-upload feed data. Disable for tests / restricted sandboxes.
    ENABLE_FEED_SCHEDULER: bool = _bool("ENABLE_FEED_SCHEDULER", "true")
    SYNC_ON_STARTUP: bool = _bool("SYNC_ON_STARTUP", "true")

    REPORTS_DIR: Path = BASE_DIR / "generated_reports"


settings = Settings()
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
settings.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
