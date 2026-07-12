from functools import lru_cache

from pydantic_settings import BaseSettings

from .environment import Environment


class Settings(BaseSettings):

    app_name: str = "SecureScan AI"

    app_version: str = "0.1.0-alpha"

    environment: Environment = Environment.DEVELOPMENT

    debug: bool = True

    host: str = "0.0.0.0"

    port: int = 8000

    mongodb_uri: str

    mongodb_database: str

    kafka_bootstrap_servers: str

    redis_url: str

    jwt_secret: str

    jwt_expiry_minutes: int = 60

    class Config:
        env_file = ".env"


@lru_cache
def get_settings():
    return Settings()