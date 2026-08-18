from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    """Runtime settings kept intentionally small for the local foundation."""

    app_name: str = "RedDock"
    version: str = "0.1.0"
    database_url: str = "sqlite:///./data/reddock.db"


@lru_cache
def get_settings() -> Settings:
    import os

    database_url = os.getenv("REDDOCK_DATABASE_URL", Settings().database_url)
    if database_url.startswith("sqlite:///") and not database_url.startswith("sqlite:////"):
        Path(database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    return Settings(database_url=database_url)

