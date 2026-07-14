"""
Global pytest fixtures.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    """
    Return a shared FastAPI test client.
    """
    return TestClient(app)