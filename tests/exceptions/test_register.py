import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from httpx import ASGITransport

from app.api.exceptions.register import register_all_errors
from app.api.exceptions.exceptions import (
    InvalidTokenPayload, InvalidToken, InvalidCredentials, UnprocessableEntityException, UserAlreadyExists,
    Unauthorized, InsufficientPermission, UserNotFound, MethodNotAllowed,
    BadRequest, AccessTokenRequired, RefreshTokenRequired, RevokedToken,
    RefreshTokenExpired, PasswordMismatchError, RegistrationInitiationFailed,
    UserDeletionFailed, RateLimiterException
)

exception_test_cases = [
    (InvalidToken, 401, "Invalid or expired token"),
    (InvalidTokenPayload, 401, "Invalid token: email missing"),
    (InvalidCredentials, 400, "Invalid credetials"),
    (UserAlreadyExists, 400, "Registration failed: Credentials cannot be accepted"),
    (Unauthorized, 401, "Unauthorized"),
    (UserNotFound, 404, "User not found"),
    (MethodNotAllowed, 405, "Method not allowed"),
    (BadRequest, 400, "Bad request"),
    (AccessTokenRequired, 401, "Access token required"),
    (RefreshTokenRequired, 401, "Refresh token required"),
    (RevokedToken, 401, "Token has been revoked, login again"),
    (InsufficientPermission, 403, "Insufficient permission"),
    (RefreshTokenExpired, 400, "Please get a valid refresh token or login again"),
    (PasswordMismatchError, 400, "Passwords do not match"),
    (RegistrationInitiationFailed, 500, "Failed to initiate registration"),
    (UserDeletionFailed, 500, "Failed to delete user due to internal error"),
    (RateLimiterException, 429, "Too many request. Please try again later"),
    (UnprocessableEntityException, 422, "Missing required field")
]

@pytest.mark.asyncio
@pytest.mark.parametrize("exception_class, expected_status, expected_message", exception_test_cases)
async def test_all_custom_exceptions(exception_class, expected_status, expected_message):
    app = FastAPI()

    @app.get("/raise")
    async def raise_error():
        raise exception_class()

    register_all_errors(app)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/raise")

    assert response.status_code == expected_status
    assert response.json() == {
        "status_code": expected_status,
        "success": False,
        "message": expected_message,
        "data": None
    }
