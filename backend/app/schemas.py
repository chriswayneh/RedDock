from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DockyardCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120, examples=["Q3 web application review"])
    description: str | None = Field(default=None, max_length=2_000)


class DockyardRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime


class HealthRead(BaseModel):
    status: str
    service: str


class VersionRead(BaseModel):
    name: str
    version: str

