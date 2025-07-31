import pytest
from fastapi import Request, Response
from starlette.datastructures import Headers
from unittest.mock import AsyncMock

from app.api.utils.build_refresh_response import build_refresh_response
from app.api.v1.schemas.auth import TokenRefreshResponse


@pytest.mark.asyncio
async def test_build_refresh_response_mobile_client(monkeypatch):
    """
    Test that a new access and refresh token are returned in the response body for mobile clients.
    """
    user = {"user": {"id": 1, "email": "test@example.com"}}

    monkeypatch.setattr(
        "app.api.utils.build_refresh_response.create_access_token",
        AsyncMock(side_effect=["new_access_token", "new_refresh_token"])
    )

    request = Request({
        "type": "http",
        "headers": Headers({"client-type": "mobile"}).raw,
    })

    response = Response()

    refresh_response: TokenRefreshResponse = await build_refresh_response(request, response, user)

    assert refresh_response.access_token == "new_access_token"
    assert refresh_response.refresh_token == "new_refresh_token"


@pytest.mark.asyncio
async def test_build_refresh_response_web_client(monkeypatch):
    """
    Test that a new access token is returned and the refresh token is set in a cookie for web clients.
    """
    user = {"user": {"id": 1, "email": "test@example.com"}}

    monkeypatch.setattr(
        "app.api.utils.build_refresh_response.create_access_token",
        AsyncMock(side_effect=["new_access_token_web", "new_refresh_token_web"])
    )

    request = Request({
        "type": "http",
        "headers": Headers({
            "client-type": "web",
            "origin": "https://example.com"
        }).raw,
    })

    response = Response()

    refresh_response: TokenRefreshResponse = await build_refresh_response(request, response, user)

    assert refresh_response.access_token == "new_access_token_web"
    assert refresh_response.refresh_token is None

    cookies = response.headers.get("set-cookie", "")
    assert "refresh_token=" in cookies
    assert "HttpOnly" in cookies


@pytest.mark.asyncio
async def test_build_refresh_response_cookie_fallback(monkeypatch):
    """
    Test that when a refresh token is found in cookie (even if not a web client), it is set again.
    """
    user = {"user": {"id": 1, "email": "test@example.com"}}

    monkeypatch.setattr(
        "app.api.utils.build_refresh_response.create_access_token",
        AsyncMock(side_effect=["access_token_cookie", "refresh_token_cookie"])
    )

    request = Request({
        "type": "http",
        "headers": Headers({
            "client-type": "mobile",
            "origin": "https://example.com"
        }).raw,
    })

    response = Response()

    refresh_response: TokenRefreshResponse = await build_refresh_response(
        request, response, user, refresh_cookie="old_token"
    )

    assert refresh_response.access_token == "access_token_cookie"
    assert refresh_response.refresh_token is None

    cookies = response.headers.get("set-cookie", "")
    assert "refresh_token=" in cookies
    assert "HttpOnly" in cookies
