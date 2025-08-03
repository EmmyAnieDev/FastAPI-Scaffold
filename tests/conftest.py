import asyncio
from typing import AsyncIterator
from httpx import AsyncClient
import pytest

from fastapi.testclient import TestClient
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession
from main import app


@pytest.fixture
def client():
    """Fixture for FastAPI TestClient."""
    return TestClient(app)


@pytest.fixture
def mock_db_session():
    """Fixture for mocking SQLAlchemy AsyncSession."""
    return AsyncMock(spec=AsyncSession)



