import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import router
from app.config import get_settings
from app.database import SessionLocal, initialize_database
from app.discovery.runner import recover_interrupted_runs

STATIC_DIRECTORY = Path(__file__).resolve().parents[2] / "static"

logger = logging.getLogger("reddock")


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    with SessionLocal() as session:
        # A run that was in flight when the process stopped did not finish.
        # Saying so is more useful than leaving it looking active forever.
        interrupted = recover_interrupted_runs(session)
    if interrupted:
        logger.warning("Marked %s discovery run(s) as interrupted by restart", interrupted)
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
