from datetime import datetime
from typing import Any


class ErrorResponse:
    def __init__(
        self,
        status: int,
        error: str,
        message: str,
        path: str,
        details: Any = None,
    ):
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.status = status
        self.error = error
        self.message = message
        self.path = path
        self.details = details

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "status": self.status,
            "error": self.error,
            "message": self.message,
            "path": self.path,
            "details": self.details,
        }