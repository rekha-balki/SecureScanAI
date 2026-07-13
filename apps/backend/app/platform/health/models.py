from pydantic import BaseModel


class ComponentHealth(BaseModel):
    name: str
    status: str
    details: dict = {}


class HealthStatus(BaseModel):
    application: ComponentHealth