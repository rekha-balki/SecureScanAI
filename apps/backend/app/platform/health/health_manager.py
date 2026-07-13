from app.platform.health.checks.application_check import application_check
from app.platform.health.models import HealthStatus


class HealthManager:

    @staticmethod
    def get_health() -> HealthStatus:

        return HealthStatus(
            application=application_check(),
        )