import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.repository import ReportRepository
from app.services import report_service
from app.services.serializers import serialize_report
from app.services.url_service import get_hostname
from app.schemas.investigation import Report as ReportSchema, CreateReportRequest

router = APIRouter(prefix="/reports", tags=["reports"])

_EXTENSIONS = {"PDF": "pdf", "JSON": "json", "HTML": "html"}

# Windows forbids \ / : * ? " < > | in filenames (plus trailing dots/spaces),
# so the download name is built from ASCII-safe parts only -- this matters
# because the frontend downloads this straight to disk via a browser "Save
# As", and an invalid character here silently breaks the save on Windows.
_UNSAFE_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|]+')


def _download_filename(report) -> str:
    ext = _EXTENSIONS.get(report.format, "bin")
    inv = report.investigation
    if inv is not None:
        host = get_hostname(inv.normalized_target) or inv.normalized_target
        verdict = inv.risk_verdict or "unknown"
    else:
        host, verdict = "unknown-target", "unknown"
    host = _UNSAFE_FILENAME_CHARS.sub("-", host).strip(" .") or "unknown-target"
    verdict = _UNSAFE_FILENAME_CHARS.sub("-", verdict).strip(" .") or "unknown"
    return f"phishscan-{host}-{verdict}-{report.id}.{ext}"


@router.get("", response_model=list[ReportSchema])
def list_reports(db: Session = Depends(get_db)):
    repo = ReportRepository(db)
    return [serialize_report(r) for r in repo.list()]


@router.post("", response_model=ReportSchema)
def create_report(payload: CreateReportRequest, db: Session = Depends(get_db)):
    try:
        report = report_service.create_report(db, payload.investigation_id, payload.format)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return serialize_report(report)


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    repo = ReportRepository(db)
    report = repo.get(report_id)
    if report is None or not report.file_path:
        raise HTTPException(status_code=404, detail="Report not found")
    media_types = {"PDF": "application/pdf", "JSON": "application/json", "HTML": "text/html"}
    return FileResponse(
        report.file_path,
        media_type=media_types.get(report.format, "application/octet-stream"),
        filename=_download_filename(report),
        content_disposition_type="attachment",
    )
