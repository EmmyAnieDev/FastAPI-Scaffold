import pytest

from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
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


@pytest.fixture(autouse=True)
def mock_redis_services():
    """Automatically mock Redis services for all tests."""
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.incr.return_value = 1
    mock_redis.expire.return_value = True
    mock_redis.sadd.return_value = 1
    mock_redis.sismember.return_value = False

    with patch("app.api.v1.services.rate_limiter.redis_client", mock_redis), \
         patch("app.api.core.redis.redis_client", mock_redis):
        yield
