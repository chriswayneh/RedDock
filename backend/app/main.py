import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import router
from app.config import get_settings
from app.correlation.runner import recover_interrupted_runs as recover_interrupted_correlations
from app.database import SessionLocal, initialize_database
from app.detection.registry import available_detectors
from app.detection.runner import recover_interrupted_runs as recover_interrupted_detections
from app.discovery.runner import recover_interrupted_runs
from app.intelligence.runner import recover_interrupted_runs as recover_interrupted_intelligence
from app.reporting.runner import recover_interrupted_runs as recover_interrupted_reports
from app.response_security import ResponseSecurityMiddleware
from app.validation.runner import recover_interrupted_runs as recover_interrupted_validations

STATIC_DIRECTORY = Path(__file__).resolve().parents[2] / "static"

logger = logging.getLogger("reddock")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Deployment-owned detector manifests are frozen and validated before the
    # service accepts traffic. A malformed extension fails startup closed.
    available_detectors()
    initialize_database()
    with SessionLocal() as session:
        # A run that was in flight when the process stopped did not finish.
        # Saying so is more useful than leaving it looking active forever, and a
        # detection run left active would keep refusing the next one.
        interrupted = recover_interrupted_runs(session)
        detections = recover_interrupted_detections(session)
        correlations = recover_interrupted_correlations(session)
        intelligence = recover_interrupted_intelligence(session)
        reports = recover_interrupted_reports(session)
        validations = recover_interrupted_validations(session)
    if interrupted:
        logger.warning("Marked %s discovery run(s) as interrupted by restart", interrupted)
    if detections:
        logger.warning("Marked %s detection run(s) as interrupted by restart", detections)
    if correlations:
        logger.warning("Marked %s correlation run(s) as interrupted by restart", correlations)
    if intelligence:
        logger.warning("Marked %s intelligence run(s) as interrupted by restart", intelligence)
    if reports:
        logger.warning("Marked %s report run(s) as interrupted by restart", reports)
    if validations:
        logger.warning("Marked %s validation run(s) as interrupted by restart", validations)
    yield


def frontend(path: str):
    if path.split("/", 1)[0] in {"api", "docs", "redoc", "openapi.json"}:
        raise HTTPException(status_code=404, detail="Not found")
    index = STATIC_DIRECTORY / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "RedDock API is running. Build the frontend to serve the UI."}


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="RedDock Core",
        version=settings.version,
        lifespan=lifespan,
        docs_url="/docs" if settings.api_docs_enabled else None,
        redoc_url="/redoc" if settings.api_docs_enabled else None,
        openapi_url="/openapi.json" if settings.api_docs_enabled else None,
    )
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1"],
        www_redirect=False,
    )
    # Wrap even rejected Host requests in the strict application policy.
    application.add_middleware(ResponseSecurityMiddleware, docs_enabled=settings.api_docs_enabled)
    application.include_router(router)

    # /assets is also an application page. Register its exact paths before
    # the bundle mount so refreshing the inventory does not become a static 404.
    @application.get("/assets", include_in_schema=False)
    @application.get("/assets/", include_in_schema=False)
    def asset_page():
        return frontend("assets")

    if STATIC_DIRECTORY.exists():
        application.mount(
            "/assets", StaticFiles(directory=STATIC_DIRECTORY / "assets"), name="assets"
        )
    application.add_api_route("/{path:path}", frontend, methods=["GET"], include_in_schema=False)
    return application


app = create_app()
