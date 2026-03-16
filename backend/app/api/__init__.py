from fastapi import APIRouter

from app.api.incidents import router as incidents_router
from app.api.risks import router as risks_router
from app.api.twin import router as twin_router
from app.api.ledger import router as ledger_router
from app.api.playbooks import router as playbooks_router
from app.api.assets import router as assets_router
from app.api.dashboard import router as dashboard_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(incidents_router, prefix="/incidents", tags=["incidents"])
api_router.include_router(risks_router, prefix="/risks", tags=["risks"])
api_router.include_router(twin_router, prefix="/twin", tags=["digital-twin"])
api_router.include_router(ledger_router, prefix="/ledger", tags=["ledger"])
api_router.include_router(playbooks_router, prefix="/playbooks", tags=["playbooks"])
api_router.include_router(assets_router, prefix="/assets", tags=["assets"])
api_router.include_router(dashboard_router, tags=["dashboard"])
