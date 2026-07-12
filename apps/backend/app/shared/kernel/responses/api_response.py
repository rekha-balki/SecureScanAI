from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Any | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)