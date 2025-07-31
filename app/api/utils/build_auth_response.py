from fastapi import Request, Response
from datetime import timedelta

from app.api.v1.schemas.auth import AuthResponse
from config import settings
from app.api.utils.token import create_access_token


async def build_auth_response(user, request: Request, response: Response) -> AuthResponse:
    """
    Generate access and refresh tokens and handle client-specific response formats.

    Args:
        user: The user object.
        request (Request): Incoming request to determine client type.
        response (Response): FastAPI response object.

    Returns:
        AuthResponse: Response data with appropriate tokens.
    """

    access_token = await create_access_token({"id": str(user.id), "email": user.email})
    refresh_token = await create_access_token(
        {"id": str(user.id), "email": user.email},
        refresh=True,
        expiry=timedelta(days=settings.REFRESH_TOKEN_EXPIRY),
    )

    client_type = request.headers.get("client-type")
    origin = request.headers.get("origin", "")
    domain = None if "localhost" in origin else settings.COOKIE_DOMAIN

    if client_type == "web":
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=not settings.DEBUG,
            max_age=settings.COOKIE_MAX_AGE,
            domain=domain,
            path="/",
            samesite="lax",
        )
        return AuthResponse(
            id=str(user.id),
            email=user.email,
            created_at=user.created_at,
            access_token=access_token,
            refresh_token=None,
        )

    else:
        return AuthResponse(
            id=str(user.id),
            email=user.email,
            created_at=user.created_at,
            access_token=access_token,
            refresh_token=refresh_token,
        )
