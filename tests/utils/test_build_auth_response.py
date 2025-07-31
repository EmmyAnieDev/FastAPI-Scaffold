import pytest
from fastapi import Request, Response
from starlette.datastructures import Headers
from datetime import datetime
from unittest.mock import AsyncMock

from app.api.utils.build_auth_response import build_auth_response
from app.api.v1.schemas.auth import AuthResponse


class DummyUser:
    def __init__(self):
        self.id = 1
        self.email = "test@example.com"
        self.created_at = datetime.utcnow()


@pytest.mark.asyncio
async def test_build_auth_response_mobile_client(monkeypatch):
    """
    Test token generation and response structure for mobile clients.
    Ensures both access and refresh tokens are returned in the response.
    """
    user = DummyUser()
    monkeypatch.setattr(
        "app.api.utils.build_auth_response.create_access_token",
        AsyncMock(side_effect=["access123", "refresh123"])
    )

    request = Request({
        "type": "http",
        "headers": Headers({"client-type": "mobile"}).raw,
    })

    response = Response()
    auth_response: AuthResponse = await build_auth_response(user, request, response)

    assert auth_response.access_token == "access123"
    assert auth_response.refresh_token == "refresh123"
    assert auth_response.email == user.email
    assert auth_response.id == str(user.id)
    assert isinstance(auth_response.created_at, datetime)


@pytest.mark.asyncio
async def test_build_auth_response_web_client(monkeypatch):
    """
    Test token generation and cookie handling for web clients.
    Ensures refresh token is stored in a cookie and not returned in the response.
    """
    user = DummyUser()
    monkeypatch.setattr(
        "app.api.utils.build_auth_response.create_access_token",
        AsyncMock(side_effect=["access456", "refresh456"])
    )

    request = Request({
        "type": "http",
        "headers": Headers({
            "client-type": "web",
            "origin": "https://example.com"
        }).raw,
    })

    response = Response()
    auth_response: AuthResponse = await build_auth_response(user, request, response)

    assert auth_response.access_token == "access456"
    assert auth_response.refresh_token is None
    assert auth_response.email == user.email
    assert auth_response.id == str(user.id)

    cookies = response.headers.get("set-cookie", "")
    assert "refresh_token=" in cookies
    assert "HttpOnly" in cookies
