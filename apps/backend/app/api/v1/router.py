from fastapi import APIRouter

from app.api.v1.routes.health import health_router
from app.api.v1.routes.application import application_router

api_v1_router = APIRouter()

api_v1_router.include_router(application_router)
api_v1_router.include_router(health_router)