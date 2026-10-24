from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field

CamelModel = lambda: ConfigDict(populate_by_name=True, from_attributes=True)  # noqa: E731


class ThreatIntelMatch(BaseModel):
    model_config = CamelModel()
    source: Literal["phishtank", "openphish"]
    matched_on: Literal["url", "domain"] = Field(alias="matchedOn")
    target: Optional[str] = None
    verified: Optional[bool] = None
    online: Optional[bool] = None
    first_seen: datetime = Field(alias="firstSeen")
    last_seen: datetime = Field(alias="lastSeen")


class ThreatIntelCheckResponse(BaseModel):
    model_config = CamelModel()
    matched: bool
    url: str
    normalized_url: Optional[str] = Field(default=None, alias="normalizedUrl")
    domain: Optional[str] = None
    records: list[ThreatIntelMatch] = Field(default_factory=list)


class FeedSyncResult(BaseModel):
    model_config = CamelModel()
    source: str
    status: str
    records_seen: Optional[int] = Field(default=None, alias="recordsSeen")
    records_new: Optional[int] = Field(default=None, alias="recordsNew")
    message: Optional[str] = None
