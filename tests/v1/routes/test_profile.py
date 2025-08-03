import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport
from fastapi import status
from main import app


def dummy_rate_limiter(func):
    """Bypass the actual rate limiter during tests."""
    return func


@pytest.mark.asyncio(scope="session")
@patch("app.api.v1.routes.profile.UserService.get_user_by_email", new_callable=AsyncMock)
async def test_get_user_profile_success(mock_get_user_by_email):
    """
    Test successful retrieval of authenticated user's profile.
    """
    mock_user = AsyncMock()
    mock_user.email = "test@example.com"
    mock_user.id = "user-id"
    mock_user.created_at = "2025-01-01T00:00:00Z"
    mock_get_user_by_email.return_value = mock_user

    token_data = {
        "user": {
            "email": "test@example.com"
        }
    }

    with patch("app.api.v1.routes.profile.AccessTokenBearer.__call__", return_value=token_data):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/api/v1/users/me")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "User profile retrieved successfully"


@pytest.mark.asyncio(scope="session")
@patch("app.api.v1.routes.profile.rate_limiter", dummy_rate_limiter)
@patch("app.api.v1.routes.profile.UserService.get_user_by_email", new_callable=AsyncMock)
@patch("app.api.v1.routes.profile.UserService.update_user", new_callable=AsyncMock)
async def test_update_profile_success(mock_update_user, mock_get_user_by_email):
    """
    Test successful profile update.
    """
    mock_user = AsyncMock()
    mock_user.email = "test@example.com"
    mock_user.id = "user-id"
    mock_user.created_at = "2025-01-01T00:00:00Z"

    mock_get_user_by_email.return_value = mock_user
    mock_update_user.return_value = mock_user

    token_data = {
        "user": {
            "email": "test@example.com"
        }
    }

    with patch("app.api.v1.routes.profile.AccessTokenBearer.__call__", return_value=token_data):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.put(
                "/api/v1/users/me",
                json={"email": "new@example.com"}
            )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "User profile updated successfully"


@pytest.mark.asyncio(scope="session")
@patch("app.api.v1.routes.profile.rate_limiter", dummy_rate_limiter)
@patch("app.api.v1.routes.profile.UserService.get_user_by_email", new_callable=AsyncMock)
@patch("app.api.v1.routes.profile.UserService.delete_user", new_callable=AsyncMock)
async def test_delete_profile_success(mock_delete_user, mock_get_user_by_email):
    """
    Test successful profile deletion.
    """
    mock_user = AsyncMock()
    mock_user.email = "test@example.com"
    mock_user.id = "user-id"

    mock_get_user_by_email.return_value = mock_user
    mock_delete_user.return_value = True

    token_data = {
        "user": {
            "email": "test@example.com"
        }
    }

    with patch("app.api.v1.routes.profile.AccessTokenBearer.__call__", return_value=token_data):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.delete("/api/v1/users/me")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "User account deleted successfully"
