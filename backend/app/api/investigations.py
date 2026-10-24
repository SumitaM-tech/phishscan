from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.repository import InvestigationRepository
from app.services import investigation_service
from app.services.serializers import serialize_investigation
from app.schemas.investigation import Investigation as InvestigationSchema, CreateInvestigationRequest

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.post("", response_model=InvestigationSchema)
def create_investigation(payload: CreateInvestigationRequest, db: Session = Depends(get_db)):
    try:
        inv = investigation_service.run_investigation(db, payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return serialize_investigation(inv)


@router.get("", response_model=list[InvestigationSchema])
def list_investigations(db: Session = Depends(get_db)):
    repo = InvestigationRepository(db)
    return [serialize_investigation(inv) for inv in repo.list()]


@router.get("/{investigation_id}", response_model=InvestigationSchema)
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    repo = InvestigationRepository(db)
    inv = repo.get(investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return serialize_investigation(inv)
