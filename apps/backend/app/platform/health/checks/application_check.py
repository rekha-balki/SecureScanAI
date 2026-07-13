from app.config.settings import get_settings
from app.platform.health.models import ComponentHealth

settings = get_settings()


def application_check() -> ComponentHealth:

    return ComponentHealth(
        name="SecureScan AI",
        status="UP",
        details={
            "version": settings.app_version,
            "environment": settings.environment,
        },
    )