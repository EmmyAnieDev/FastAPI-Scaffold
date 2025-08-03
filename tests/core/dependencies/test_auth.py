import pytest
from fastapi import Request
from starlette.datastructures import Headers
from unittest.mock import AsyncMock

from app.api.core.dependencies.auth import (
    AccessTokenBearer,
    RefreshTokenBearer,
    TokenBearer,
    get_current_user,
    CheckRole
)
from app.api.v1.models.users import User
from app.api.exceptions.register import (
    AccessTokenRequired, RefreshTokenRequired, InvalidTokenPayload,
    UserNotFound, InsufficientPermission
)

def test_token_valid_with_valid_token(monkeypatch):
    """
    Returns True if decode_token returns a valid payload.
    """
    monkeypatch.setattr("app.api.core.dependencies.auth.decode_token", lambda token: {"user": {"email": "valid@example.com"}})
    assert TokenBearer.token_valid("fake-token") is True

def test_token_valid_with_invalid_token(monkeypatch):
    """
    Returns False if decode_token returns None.
    """
    monkeypatch.setattr("app.api.utils.token.decode_token", lambda token: None)
    assert TokenBearer.token_valid("fake-token") is False

def test_base_class_verify_token_data_raises():
    """
    Raises NotImplementedError if verify_token_data is not overridden.
    """
    with pytest.raises(NotImplementedError):
        TokenBearer.verify_token_data({"refresh": False})

def test_access_token_bearer_rejects_refresh_token():
    """
    Raises AccessTokenRequired if a refresh token is passed to AccessTokenBearer.
    """
    with pytest.raises(AccessTokenRequired):
        AccessTokenBearer.verify_token_data({"refresh": True})

def test_access_token_bearer_accepts_access_token():
    """
    Accepts access token (no exception raised).
    """
    AccessTokenBearer.verify_token_data({"refresh": False})

def test_refresh_token_bearer_accepts_refresh_token():
    """
    Accepts refresh token (no exception raised).
    """
    RefreshTokenBearer.verify_token_data({"refresh": True})

def test_refresh_token_bearer_rejects_access_token():
    """
    Raises RefreshTokenRequired if access token is passed to RefreshTokenBearer.
    """
    with pytest.raises(RefreshTokenRequired):
        RefreshTokenBearer.verify_token_data({"refresh": False})

@pytest.mark.asyncio
async def test_access_token_bearer_valid_token(monkeypatch):
    """
    Returns decoded token data if token is valid and not blacklisted.
    """
    token_data = {
        "user": {"email": "test@example.com"},
        "jti": "test-jti",
        "refresh": False
    }

    monkeypatch.setattr("app.api.utils.token.decode_token", lambda token: token_data)
    monkeypatch.setattr("app.api.core.dependencies.auth.decode_token", lambda token: token_data)
    monkeypatch.setattr("app.api.core.dependencies.auth.jti_in_blocklist", AsyncMock(return_value=False))

    class DummyAuth:
        credentials = "fake-token"

    monkeypatch.setattr(
        "app.api.core.dependencies.auth.HTTPBearer.__call__",
        AsyncMock(return_value=DummyAuth())
    )

    request = Request({
        "type": "http",
        "headers": Headers({"authorization": "Bearer fake-token"}).raw,
    })

    bearer = AccessTokenBearer()
    result = await bearer.__call__(request)

    assert result["user"]["email"] == "test@example.com"

@pytest.mark.asyncio
async def test_refresh_token_bearer_invalid(monkeypatch):
    """
    Raises RefreshTokenRequired if access token is passed to RefreshTokenBearer.
    """
    token_data = {
        "user": {"email": "test@example.com"},
        "jti": "test-jti",
        "refresh": False
    }

    monkeypatch.setattr("app.api.utils.token.decode_token", lambda token: token_data)
    monkeypatch.setattr("app.api.core.dependencies.auth.decode_token", lambda token: token_data)
    monkeypatch.setattr("app.api.core.dependencies.auth.jti_in_blocklist", AsyncMock(return_value=False))

    class DummyAuth:
        credentials = "fake-token"

    monkeypatch.setattr(
        "app.api.core.dependencies.auth.HTTPBearer.__call__",
        AsyncMock(return_value=DummyAuth())
    )

    request = Request({
        "type": "http",
        "headers": Headers({"authorization": "Bearer fake-token"}).raw,
    })

    with pytest.raises(RefreshTokenRequired):
        bearer = RefreshTokenBearer()
        await bearer.__call__(request)

@pytest.mark.asyncio
async def test_get_current_user_success(monkeypatch):
    """
    Returns a valid User if user is found and email is present in token.
    """
    token_data = {
        "user": {"email": "test@example.com"},
        "jti": "test-jti",
        "refresh": False
    }

    dummy_user = User(id=1, email="test@example.com", password_hash="hashedpass")

    monkeypatch.setattr("app.api.utils.token.decode_token", lambda token: token_data)
    monkeypatch.setattr("app.api.core.redis.jti_in_blocklist", AsyncMock(return_value=False))
    monkeypatch.setattr("app.api.v1.services.users.UserService.get_user_by_email", AsyncMock(return_value=dummy_user))

    db_mock = AsyncMock()
    result = await get_current_user(token_details=token_data, db=db_mock)

    assert result.email == "test@example.com"

@pytest.mark.asyncio
async def test_get_current_user_missing_email(monkeypatch):
    """
    Raises InvalidTokenPayload if 'email' is missing in token user data.
    """
    token_data = {
        "user": {},
        "jti": "test-jti",
        "refresh": False
    }

    db_mock = AsyncMock()

    with pytest.raises(InvalidTokenPayload):
        await get_current_user(token_details=token_data, db=db_mock)

@pytest.mark.asyncio
async def test_get_current_user_user_not_found(monkeypatch):
    """
    Raises UserNotFound if user is not found in DB.
    """
    token_data = {
        "user": {"email": "ghost@example.com"},
        "jti": "test-jti",
        "refresh": False
    }

    monkeypatch.setattr("app.api.v1.services.users.UserService.get_user_by_email", AsyncMock(return_value=None))
    db_mock = AsyncMock()

    with pytest.raises(UserNotFound):
        await get_current_user(token_details=token_data, db=db_mock)

@pytest.mark.asyncio
async def test_check_role_allows(monkeypatch):
    """
    Allows access if user's role is in allowed_roles.
    """
    dummy_user = User(id=1, email="admin@example.com", password_hash="hashedpass")
    dummy_user.role = "admin"

    monkeypatch.setattr("app.api.core.dependencies.auth.get_current_user", AsyncMock(return_value=dummy_user))

    check_role = CheckRole(allowed_roles=["admin", "manager"])
    result = await check_role(current_user=dummy_user)
    assert result is True

@pytest.mark.asyncio
async def test_check_role_rejects(monkeypatch):
    """
    Raises InsufficientPermission if user's role is not allowed.
    """
    dummy_user = User(id=2, email="user@example.com", password_hash="hashedpass")
    dummy_user.role = "user"

    monkeypatch.setattr("app.api.core.dependencies.auth.get_current_user", AsyncMock(return_value=dummy_user))

    check_role = CheckRole(allowed_roles=["admin", "manager"])

    with pytest.raises(InsufficientPermission):
        await check_role(current_user=dummy_user)