"""
MongoDB collection registry.

Defines all collection names used by SecureScan AI.
"""


class Collections:
    """
    MongoDB collection names.
    """

    USERS = "users"

    COMPANIES = "companies"

    ROLES = "roles"

    PERMISSIONS = "permissions"

    PROJECTS = "projects"

    TARGETS = "targets"

    SCANS = "scans"

    SCAN_JOBS = "scan_jobs"

    FINDINGS = "findings"

    REPORTS = "reports"

    TEMPLATES = "templates"

    AUDIT_LOGS = "audit_logs"

    SETTINGS = "settings"

    NOTIFICATIONS = "notifications"

    PASSWORD_RESETS = "password_resets"

    ATTACK_SURFACE = "attack_surface"
    
from motor.motor_asyncio import AsyncIOMotorCollection

from app.platform.persistence.mongodb.database import (
    get_database,
)


def get_collection(name: str) -> AsyncIOMotorCollection:
    """
    Return a MongoDB collection.
    """

    return get_database()[name]