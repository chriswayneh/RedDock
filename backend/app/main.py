from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import router
from app.config import get_settings
from app.database import initialize_database

STATIC_DIRECTORY = Path(__file__).resolve().parents[2] / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


settings = get_settings()
app = FastAPI(title="RedDock Core", version=settings.version, lifespan=lifespan)
app.include_router(router)

if STATIC_DIRECTORY.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIRECTORY / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def frontend(path: str):
    index = STATIC_DIRECTORY / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "RedDock API is running. Build the frontend to serve the UI."}

