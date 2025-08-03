import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, patch
from fastapi import status
from main import app


def dummy_rate_limiter(func):
    """
    Dummy rate limiter to bypass actual limiter in tests
    """
    return func


@pytest.mark.asyncio(scope="session")
@patch("app.api.v1.routes.auth.rate_limiter", dummy_rate_limiter)
@patch("app.api.v1.services.users.UserService.user_exists", new_callable=AsyncMock)
@patch("app.api.v1.services.users.UserService.register_user", new_callable=AsyncMock)
@patch("app.api.utils.build_auth_response", new_callable=AsyncMock)
async def test_register_success(
    mock_auth_response, mock_register_user, mock_user_exists
):
    """Test user registration with valid credentials."""
    mock_user_exists.return_value = False
    mock_user = AsyncMock()
    mock_user.email = "test@example.com"
    mock_register_user.return_value = mock_user
    mock_auth_response.return_value = {"access_token": "fake_token"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/auth/register",
            json={"email": "test@example.com", "password": "strongpassword"},
        )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["message"] == "User Registered Successfully"


@pytest.mark.asyncio(scope="session")
async def test_login_success(monkeypatch):
    """Test user login with valid email and password."""
    async def mock_get_user_by_email(email, db):
        mock_user = AsyncMock()
        mock_user.email = email
        mock_user.password_hash = "$2b$12$KIXQ.tNh0DG.ZVEBPvtOWOCqX1iEAGC6e1e3PYhLUba6dHpZ0Cjdi"
        return mock_user

    def mock_verify_password(plain, hashed):
        return True

    async def mock_build_auth_response(user, request, response):
        return {
            "id": "fake-id",
            "email": user.email,
            "created_at": "2025-01-01T00:00:00Z",
            "access_token": "fake_token"
        }

    monkeypatch.setattr("app.api.v1.routes.auth.verify_password", mock_verify_password)
    monkeypatch.setattr("app.api.v1.services.users.UserService.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("app.api.v1.routes.auth.build_auth_response", mock_build_auth_response)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "strongpassword"},
        )

    assert response.status_code == 200
    assert response.json()["message"] == "User logged in Successfully"


@pytest.mark.asyncio(scope="session")
@patch("app.api.v1.routes.auth.rate_limiter", dummy_rate_limiter)
@patch("app.api.core.dependencies.auth.RefreshTokenBearer.__call__", new_callable=AsyncMock)
@patch("app.api.utils.build_refresh_response", new_callable=AsyncMock)
async def test_refresh_token_success(
    mock_build_refresh_response,
    mock_refresh_token_bearer,
):
    """Test token refresh using a valid refresh token."""
    mock_refresh_token_bearer.return_value = {
        "user": {"id": "123", "email": "test@example.com"},
        "jti": "test-jti",
        "refresh": True
    }
    mock_build_refresh_response.return_value = {
        "access_token": "new_access_token",
        "refresh_token": "new_refresh_token",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/auth/tokens/refresh")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Token refreshed successfully"
    assert "access_token" in response.json()["data"]


@pytest.mark.asyncio(scope="session")
@patch("app.api.core.redis.add_jti_to_blocklist", new_callable=AsyncMock)
@patch("app.api.core.dependencies.auth.AccessTokenBearer.__call__", new_callable=AsyncMock)
async def test_logout_success(
    mock_access_token_bearer,
    mock_add_jti,
):
    """Test user logout with a valid access token."""
    mock_access_token_bearer.return_value = {"jti": "test-jti"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/auth/logout")

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "User logged out Successfully"
