from fastapi import FastAPI

from app.platform.security.cors import register_cors
from app.platform.security.trusted_hosts import register_trusted_hosts


def register_security(app: FastAPI) -> None:
    """Register all security middleware."""

    register_cors(app)
    register_trusted_hosts(app)