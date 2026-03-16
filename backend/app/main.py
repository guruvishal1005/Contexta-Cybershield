import logging
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.config import settings
from app.database import engine, get_db, async_session_factory
from app.models.base import Base
from app.api import api_router
from app.ledger import ledger
from app.twin import digital_twin

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

_start_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _start_time
    _start_time = time.time()
    logger.info("Starting Contexta SOC Platform")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured")

    async with async_session_factory() as db:
        await ledger.load_from_db(db)
        await digital_twin.load_from_db(db)

    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.date import DateTrigger
    from app.ingestion.cve_collector import run as cve_run

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        cve_run,
        IntervalTrigger(hours=settings.cve_collection_interval_hours),
        id="cve_collector",
        replace_existing=True,
    )
    scheduler.add_job(
        cve_run,
        DateTrigger(run_date=datetime.now(timezone.utc) + timedelta(seconds=30)),
        id="cve_collector_initial",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Scheduler started — CVE sync every %d hours", settings.cve_collection_interval_hours)

    app.state.scheduler = scheduler

    yield

    scheduler.shutdown(wait=False)
    await engine.dispose()
    logger.info("Shutdown complete")


app = FastAPI(
    title="Contexta SOC Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

from app.api.demo import router as demo_router
app.include_router(demo_router)


@app.get("/api/ml/health", tags=["ml"])
async def ml_health_stub():
    return {
        "status": "healthy",
        "model_version": "1.0.0-stub",
        "accuracy": 0.94,
        "f1Score": 0.91,
        "auc": 0.96,
        "drift": 0.02,
        "note": "ML microservice not yet deployed",
        "series": [],
    }


@app.get("/health", tags=["health"])
async def health_check():
    db_ok = False
    try:
        async with async_session_factory() as db:
            await db.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
            db_ok = True
    except Exception:
        pass

    return {
        "status": "ok",
        "db_connected": db_ok,
        "ledger_block_count": ledger.block_count,
        "uptime_seconds": round(time.time() - _start_time, 2),
    }
