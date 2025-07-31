from fastapi import Request, Response
from datetime import timedelta
from typing import Optional

from config import settings
from app.api.v1.schemas.auth import TokenRefreshResponse
from app.api.utils.token import create_access_token


async def build_refresh_response(
    request: Request,
    response: Response,
    user: dict,
    refresh_cookie: Optional[str] = None
) -> TokenRefreshResponse:
    """
    Generate new access and refresh tokens and attach refresh token as a cookie if needed.

    Args:
        request (Request): The incoming HTTP request.
        response (Response): The outgoing HTTP response to modify.
        user (dict): The user data decoded from the refresh token.
        refresh_cookie (Optional[str]): The refresh token from cookie, if available.

    Returns:
        TokenRefreshResponse: A response containing a new access token,
                              and possibly a new refresh token depending on client type.
    """
    payload = {
        "id": str(user["user"]["id"]),
        "email": user["user"]["email"]
    }

    # Create new access and refresh tokens
    access_token = await create_access_token(payload)
    refresh_token = await create_access_token(
        payload,
        refresh=True,
        expiry=timedelta(days=settings.REFRESH_TOKEN_EXPIRY)
    )

    client_type = request.headers.get("client-type")
    origin = request.headers.get("origin", "")
    domain = None if "localhost" in origin else settings.COOKIE_DOMAIN

    # If it's a web client or refresh token is from cookie, set a new refresh token in cookie
    if client_type == "web" or refresh_cookie:
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
        return TokenRefreshResponse(access_token=access_token, refresh_token=None)

    # For mobile or other clients, return refresh token in response body
    return TokenRefreshResponse(access_token=access_token, refresh_token=refresh_token)
