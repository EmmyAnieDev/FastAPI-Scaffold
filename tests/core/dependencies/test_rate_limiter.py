import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from app.api.core.dependencies.rate_limiter import rate_limiter


@pytest.fixture
def app_with_rate_limiter():
    """
    Fixture that creates a FastAPI app with the rate limiter dependency mocked.
    """
    app = FastAPI()

    with patch(
        "app.api.core.dependencies.rate_limiter.RateLimiterService.check_limit",
        new_callable=AsyncMock
    ) as mock_check_limit:
        mock_check_limit.return_value = None

        @app.get("/test", dependencies=[Depends(rate_limiter(limit=2, window=60, prefix="test"))])
        async def test_endpoint():
            return {"message": "Success"}

        yield app


def test_rate_limiter_allows_requests(app_with_rate_limiter):
    """
    Test that requests are allowed when the rate limit is not exceeded.
    """
    client = TestClient(app_with_rate_limiter)
    response = client.get("/test")
    assert response.status_code == 200
    assert response.json() == {"message": "Success"}
