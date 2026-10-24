from fastapi import APIRouter
from app.models.classifier import get_model

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    model = get_model()
    return {
        "status": "ok",
        "baselines_loaded": model.has_trained_baselines,
        "hybrid_loaded": model.has_trained_hybrid,
        "synthetic_loaded": model.has_synthetic_models,
        "backup_models_loaded": model.has_backup_models,
        "active_model_source": model.active_source,
    }
