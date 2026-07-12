from fastapi import FastAPI

from app.config.settings import get_settings
from app.platform.log import get_logger
from app.platform.errors import register_exception_handlers
from app.platform.errors.exceptions import ResourceNotFoundException
from app.shared.kernel.responses import ResponseBuilder

settings = get_settings()

logger = get_logger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)

@app.on_event("startup")
async def startup():
    logger.info("SecureScan AI started")

@app.on_event("shutdown")
async def shutdown():
    logger.info("SecureScan AI stopped")


@app.get("/")
async def root():

    logger.info("Root endpoint called")

    return ResponseBuilder.success(
        "SecureScan AI is running.",
        {
            "application": settings.app_name,
            "version": settings.app_version,
        },
    )
    
@app.get("/health")
async def health():

    return ResponseBuilder.success(
        "Health check completed successfully.",
        {
            "status": "UP",
            "environment": settings.environment,
            "version": settings.app_version,
        },
    )

register_exception_handlers(app)


@app.get("/test-error")
async def test_error():
    raise ResourceNotFoundException("Scan not found")