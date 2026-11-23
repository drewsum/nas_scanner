"""Threat-intel provider state and cached lookups."""

from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, Path
from pydantic import BaseModel, ConfigDict
from sqlalchemy import case, select

from nasscan.api.deps import DB
from nasscan.db.models import HashLookup, IntelProvider

router = APIRouter(prefix="/api/intel", tags=["intel"])


class ProviderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    kind: str
    title: str
    enabled: bool
    status: str
    message: str
    last_success: datetime | None
    last_attempt: datetime | None
    last_error: str | None
    last_error_at: datetime | None
    paused_until: datetime | None
    day: date | None
    requests_today: int
    daily_budget: int | None
    per_minute: float | None
    entries: int
    details: dict | None
    updated_at: datetime | None


class LookupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    sha256: str
    verdict: str
    name: str | None
    description: str | None
    details: dict | None
    looked_up_at: datetime
    expires_at: datetime


@router.get("/providers", response_model=list[ProviderOut])
def providers(db: DB) -> list[IntelProvider]:
    """Feeds first, then lookups; the ones that are on before the ones that are off."""
    rows = list(
        db.scalars(
            select(IntelProvider).order_by(
                case({"feed": 0}, value=IntelProvider.kind, else_=1),
                IntelProvider.enabled.desc(),
                IntelProvider.name,
            )
        )
    )
    db.expunge_all()  # detached: the reset below is only shown, never saved
    today = datetime.now(UTC).date()
    for row in rows:
        if row.day != today:
            row.requests_today = 0  # nothing yet today
    return rows


@router.get("/lookups/{sha256}", response_model=list[LookupOut])
def lookups(db: DB, sha256: Annotated[str, Path(pattern="^[0-9a-fA-F]{64}$")]) -> list[HashLookup]:
    return list(
        db.scalars(
            select(HashLookup)
            .where(HashLookup.sha256 == sha256.lower())
            .order_by(HashLookup.provider)
        )
    )
