from datetime import datetime
from typing import Any


class PageResponse:

    def __init__(
        self,
        items: list[Any],
        page: int,
        size: int,
        total_elements: int,
        total_pages: int,
    ):
        self.success = True
        self.items = items
        self.page = page
        self.size = size
        self.total_elements = total_elements
        self.total_pages = total_pages
        self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self):

        return {
            "success": self.success,
            "items": self.items,
            "page": self.page,
            "size": self.size,
            "totalElements": self.total_elements,
            "totalPages": self.total_pages,
            "timestamp": self.timestamp,
        }