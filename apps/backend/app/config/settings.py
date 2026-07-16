"""
Application configuration.

Loads and validates configuration from environment variables.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .environment import Environment


class Settings(BaseSettings):
    """
    Application settings.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    app_name: str = "SecureScan AI"
    app_version: str = "0.1.0-alpha"

    environment: Environment = Environment.DEVELOPMENT

    debug: bool = True

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    host: str = "0.0.0.0"
    port: int = 8000

    # ------------------------------------------------------------------
    # MongoDB
    # ------------------------------------------------------------------

    mongodb_uri: str = Field(..., min_length=1)

    mongodb_database: str = Field(..., min_length=1)

    mongodb_min_pool_size: int = Field(
        default=5,
        ge=1,
    )

    mongodb_max_pool_size: int = Field(
        default=20,
        ge=1,
    )

    mongodb_connect_timeout_ms: int = Field(
        default=5000,
        ge=1000,
    )

    mongodb_server_selection_timeout_ms: int = Field(
        default=5000,
        ge=1000,
    )

    # ------------------------------------------------------------------
    # Kafka
    # ------------------------------------------------------------------

    kafka_bootstrap_servers: str

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------

    redis_url: str

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------

    jwt_secret: str

    jwt_expiry_minutes: int = Field(
        default=60,
        ge=1,
    )

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    allowed_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]

    trusted_hosts: list[str] = [
        "localhost",
        "127.0.0.1",
        "testserver",  # pytest TestClient
    ]

    # ------------------------------------------------------------------
    # Rate Limiting (FRS Section 15)
    # ------------------------------------------------------------------

    rate_limit_enabled: bool = True

    rate_limit_requests_per_window: int = Field(default=120, ge=1)

    rate_limit_window_seconds: int = Field(default=60, ge=1)


@lru_cache
def get_settings() -> Settings:
    """
    Return the singleton application settings.
    """
    return Settings()


# Global singleton
settings = get_settings()