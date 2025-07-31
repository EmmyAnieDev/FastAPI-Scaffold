import logging
from fastapi import FastAPI, status
from starlette.exceptions import HTTPException as StarletteHTTPException

from .exceptions import (
    InvalidTokenPayload, InvalidToken, InvalidCredentials, UserAlreadyExists,
    Unauthorized, InsufficientPermission, UserNotFound, MethodNotAllowed,
    BadRequest, AccessTokenRequired, RefreshTokenRequired, RevokedToken,
    RefreshTokenExpired, PasswordMismatchError, RegistrationInitiationFailed,
    UserDeletionFailed
)
from .handlers import create_exception_handler

logger = logging.getLogger(__name__)


def register_all_errors(app: FastAPI):
    """
    Registers all custom exception handlers to the FastAPI app instance.

    Args:
        app (FastAPI): The main FastAPI app object.

    Returns:
        None
    """
    exception_map = {
        InvalidToken: (status.HTTP_401_UNAUTHORIZED, "Invalid or expired token"),
        InvalidTokenPayload: (status.HTTP_401_UNAUTHORIZED, "Invalid token: email missing"),
        InvalidCredentials: (status.HTTP_400_BAD_REQUEST, "Invalid credetials"),
        UserAlreadyExists: (status.HTTP_400_BAD_REQUEST, "Registration failed: Credentials cannot be accepted"),
        Unauthorized: (status.HTTP_401_UNAUTHORIZED, "Unauthorized"),
        UserNotFound: (status.HTTP_404_NOT_FOUND, "User not found"),
        MethodNotAllowed: (status.HTTP_405_METHOD_NOT_ALLOWED, "Method not allowed"),
        BadRequest: (status.HTTP_400_BAD_REQUEST, "Bad request"),
        AccessTokenRequired: (status.HTTP_401_UNAUTHORIZED, "Access token required"),
        RefreshTokenRequired: (status.HTTP_401_UNAUTHORIZED, "Refresh token required"),
        RevokedToken: (status.HTTP_401_UNAUTHORIZED, "Token has been revoked, login again"),
        InsufficientPermission: (status.HTTP_403_FORBIDDEN, "Insufficient permission"),
        RefreshTokenExpired: (status.HTTP_400_BAD_REQUEST, "Please get a valid refresh token or login again"),
        PasswordMismatchError: (status.HTTP_400_BAD_REQUEST, "Passwords do not match"),
        RegistrationInitiationFailed: (status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to initiate registration"),
        UserDeletionFailed: (status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to delete user due to internal error")
    }

    for exc_class, (code, message) in exception_map.items():
        app.add_exception_handler(exc_class, create_exception_handler(code, message))

    @app.exception_handler(500)
    async def internal_server_error(request, exc):
        logger.exception("Internal Server Error: %s", str(exc))
        return await create_exception_handler(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Internal Server Error"
        )(request, exc)

    @app.exception_handler(StarletteHTTPException)
    async def fallback_http_exception(request, exc):
        return await create_exception_handler(
            exc.status_code,
            exc.detail
        )(request, exc)