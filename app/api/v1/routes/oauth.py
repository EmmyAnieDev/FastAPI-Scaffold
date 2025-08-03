import logging

from fastapi import Request, Depends, status, Response, APIRouter
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from app.api.exceptions.exceptions import (
    BadRequest,
    InvalidToken,
    InvalidTokenPayload,
    RegistrationInitiationFailed,
)
from config import settings
from app.api.v1.schemas.auth import UserCreate, AuthResponse, GoogleMobileLoginRequest
from app.api.v1.schemas.sucess_response import SuccessResponse
from app.api.v1.services.users import UserService
from app.api.utils.success_response import success_response
from app.api.utils.build_auth_response import build_auth_response
from app.api.db.database import get_db
from app.api.core.dependencies.rate_limiter import rate_limiter
from app.api.core.oauth import oauth

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/login/google")
async def google_login(request: Request):
    """
    Initiates the OAuth login flow by redirecting the user to Google’s OAuth consent screen.

    Args:
        request (Request): FastAPI request object.

    Returns:
        RedirectResponse: Redirects the user to Google's authorization page.
    """
    redirect_uri = settings.GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get(
    "/callback/google",
    dependencies=[Depends(rate_limiter(prefix="oauth_register"))]
)
async def google_callback(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Handles the callback from Google after the user has authenticated.

    If the user is new, registers them. Then logs in the user by generating
    access and refresh tokens and sets cookies.

    Args:
        request (Request): FastAPI request object.
        response (Response): FastAPI response object.
        db (AsyncSession): Database session.

    Returns:
        RedirectResponse: Redirects to dashboard or login page based on outcome.
    """
    try:
        token = await oauth.google.authorize_access_token(request)
        id_token_str = token.get("id_token")
        if not id_token_str:
            raise InvalidTokenPayload("No id_token in token")

        user_info = id_token.verify_oauth2_token(
            id_token_str,
            google_requests.Request(),
            audience=settings.GOOGLE_WEB_CLIENT_ID
        )

    except Exception as e:
        logger.error("Google login failed: %s", str(e))
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?error=GoogleLoginFailed")

    email = user_info.get("email")
    user = await UserService.get_user_by_email(email, db)

    if not user:
        user_create = UserCreate(email=email, password=None, provider="google")
        user = await UserService.register_user(user_create, db)
        if not user:
            return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?error=RegistrationFailed")

    logger.info("Login successful for user: %s", user.email)

    # Add header to indicate web client for cookie logic
    request.scope["headers"].append((b"client-type", b"web"))

    await build_auth_response(user, request, response)

    return RedirectResponse(url=f"{settings.FRONTEND_URL}/dashboard")


@router.post(
    "/google/mobile",
    response_model=SuccessResponse[AuthResponse],
    dependencies=[Depends(rate_limiter(prefix="oauth_register"))]
)
async def google_mobile_login(
    request: Request,
    response: Response,
    login_data: GoogleMobileLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verifies a Google ID token sent from a mobile client (Android or iOS),
    and logs the user in. If the user does not exist, they are registered.

    Args:
        request (Request): FastAPI request object.
        response (Response): FastAPI response object.
        login_data (GoogleMobileLoginRequest): Contains the platform and Google ID token.
        db (AsyncSession): Database session.

    Returns:
        SuccessResponse[AuthResponse]: Auth tokens and user info wrapped in a success response.
    """
    platform = login_data.platform
    id_token_str = login_data.id_token

    if platform == "android":
        client_id = settings.GOOGLE_ANDROID_CLIENT_ID
        if not client_id:
            raise RegistrationInitiationFailed("Android Google OAuth not configured")
    elif platform == "ios":
        client_id = settings.GOOGLE_IOS_CLIENT_ID
        if not client_id:
            raise RegistrationInitiationFailed("iOS Google OAuth not configured")
    else:
        raise BadRequest("Invalid platform. Must be 'android' or 'ios'")

    try:
        id_info = id_token.verify_oauth2_token(
            id_token_str,
            google_requests.Request(),
            client_id
        )
        email = id_info.get("email")
        if not email:
            raise InvalidTokenPayload()
    except Exception as e:
        logger.exception("Google token verification failed: %s", str(e))
        raise InvalidToken()

    user = await UserService.get_user_by_email(email, db)
    if not user:
        user_create = UserCreate(email=email, provider="google")
        user = await UserService.register_user(user_create, db)
        if not user:
            raise RegistrationInitiationFailed()

    logger.info("Login successful for user: %s", user.email)

    response_data = await build_auth_response(user, request, response)

    return success_response(
        status_code=status.HTTP_200_OK,
        message="User logged in Successfully",
        data=response_data,
    )
