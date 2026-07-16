from fastapi import APIRouter

from app.api.v1.routes.application import application_router
from app.api.v1.routes.audit_logs import audit_logs_router
from app.api.v1.routes.auth import auth_router
from app.api.v1.routes.companies import companies_router
from app.api.v1.routes.health import health_router
from app.api.v1.routes.notifications import notifications_router
from app.api.v1.routes.scans import scans_router
from app.api.v1.routes.settings import settings_router
from app.api.v1.routes.users import users_router

api_v1_router = APIRouter()

api_v1_router.include_router(application_router)
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(companies_router)
api_v1_router.include_router(users_router)
api_v1_router.include_router(scans_router)
api_v1_router.include_router(notifications_router)
api_v1_router.include_router(audit_logs_router)
api_v1_router.include_router(settings_router)
