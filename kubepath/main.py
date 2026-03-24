"""FastAPI application entry point for KubePath."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from kubepath.config import settings
from kubepath.database.neo4j_client import neo4j_client
from kubepath.api.routes import router

# ── Logging ────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)-30s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("kubepath")


# ── Lifespan ───────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""
    logger.info("=" * 60)
    logger.info("  KubePath v%s — Lateral Movement Mapper", settings.version)
    logger.info("=" * 60)
    logger.info("Connecting to Neo4j at %s ...", settings.neo4j.uri)
    try:
        await neo4j_client.connect()
        logger.info("Neo4j connected successfully")
    except Exception as e:
        logger.warning("Neo4j connection failed: %s (will retry on requests)", e)

    logger.info(
        "Server running at http://%s:%d",
        settings.server.host, settings.server.port,
    )
    yield

    logger.info("Shutting down...")
    await neo4j_client.disconnect()


# ── Application ────────────────────────────────────────────────────

app = FastAPI(
    title="KubePath",
    description=(
        "Autonomous Cloud/K8s Lateral Movement Mapper — "
        "Map attack paths from compromised pods to cluster admin"
    ),
    version=settings.version,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(router)

# ── Frontend static files ──────────────────────────────────────────

frontend_dir = Path(settings.frontend_dir)
if frontend_dir.exists():
    app.mount("/css", StaticFiles(directory=str(frontend_dir / "css")), name="css")
    app.mount("/js", StaticFiles(directory=str(frontend_dir / "js")), name="js")

    @app.get("/")
    async def serve_frontend():
        """Serve the frontend index.html."""
        return FileResponse(str(frontend_dir / "index.html"))
else:
    @app.get("/")
    async def root():
        return {"message": "KubePath API", "docs": "/api/docs"}


# ── CLI entry point ────────────────────────────────────────────────

def run():
    """Run the server via CLI."""
    import uvicorn
    uvicorn.run(
        "kubepath.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=True,
    )


if __name__ == "__main__":
    run()
