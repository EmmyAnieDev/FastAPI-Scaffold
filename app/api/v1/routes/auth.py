import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, status, Depends, Request, Response, Cookie
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from app.api.v1.schemas.auth import UserCreate, UserLogin, AuthResponse, TokenRefreshResponse, LogoutResponse
from app.api.v1.schemas.sucess_response import SuccessResponse
from app.api.v1.services.users import UserService
from app.api.utils.success_response import success_response
from app.api.utils.token import verify_password
from app.api.utils.build_refresh_response import build_refresh_response
from app.api.utils.build_auth_response import build_auth_response
from app.api.exceptions.exceptions import (
    InvalidCredentials, UserAlreadyExists, RefreshTokenExpired,
    RegistrationInitiationFailed,
)
from app.api.core.dependencies.auth import RefreshTokenBearer, AccessTokenBearer
from app.api.core.redis import add_jti_to_blocklist
from app.api.db.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=SuccessResponse[AuthResponse])
async def register(
    user_data: UserCreate,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user.

    Args:
        user_data (UserCreate): New user registration details.
        request (Request): Incoming request to determine client type.
        response (Response): FastAPI response object.
        db (AsyncSession): Asynchronous SQLAlchemy session.

    Returns:
        Standard success response with AuthResponse and tokens.

    Raises:
        UserAlreadyExists: If a user already exists with the given email.
        RegistrationInitiationFailed: If user registration fails.
    """

    logger.info("Initiating registration for email: %s", user_data.email)

    if await UserService.user_exists(user_data.email, db):
        logger.warning("User already exists with email: %s", user_data.email)
        raise UserAlreadyExists()

    user = await UserService.register_user(user_data, db)

    if not user:
        logger.error("Registration initiation failed for email: %s", user_data.email)
        raise RegistrationInitiationFailed()

    logger.info("Registration successful for email: %s", user.email)

    response_data = await build_auth_response(user, request, response)
    
    return success_response(
        status_code=status.HTTP_201_CREATED,
        message="User Registered Successfully",
        data=response_data,
    )


@router.post("/login", status_code=status.HTTP_200_OK, response_model=SuccessResponse[AuthResponse])
async def login(
    data: UserLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and issue JWT tokens.

    This endpoint verifies the user's email and password. If valid,
    it returns access and refresh tokens.

    Args:
        data (UserLogin): Login credentials.
        request (Request): Incoming request to determine client type.
        response (Response): FastAPI response object.
        db (AsyncSession): Async database session.

    Returns:
        Standard success response with AuthResponse and tokens.

    Raises:
        InvalidCredentials: If authentication fails due to wrong credentials.
    """
    logger.info("Login attempt for user: %s", data.email)

    user = await UserService.get_user_by_email(data.email, db)
    if not user:
        logger.warning("User not found: %s", data.email)
        raise InvalidCredentials()

    if not verify_password(data.password, user.password_hash):
        logger.warning("Invalid password for user: %s", data.email)
        raise InvalidCredentials()

    logger.info("Login successful for user: %s", user.email)

    response_data = await build_auth_response(user, request, response)

    return success_response(
        status_code=status.HTTP_200_OK,
        message="User logged in Successfully",
        data=response_data,
    )


@router.post("/tokens/refresh", status_code=status.HTTP_200_OK, response_model=SuccessResponse[TokenRefreshResponse])
async def refresh_token(
    request: Request,
    response: Response,
    refresh_cookie: Optional[str] = Cookie(default=None),
    token_data: dict = Depends(RefreshTokenBearer())
):
    """
    Endpoint to refresh an expired or expiring access token using a refresh token.

    This endpoint:
    - Accepts a refresh token either from an Authorization header or a secure HTTP-only cookie.
    - Returns a new access token.
    - For web clients, sets a new refresh token in the cookie.
    - For other clients (e.g., mobile), includes the new refresh token in the response body.

    Args:
        request (Request): The FastAPI request object.
        response (Response): The FastAPI response object.
        refresh_cookie (Optional[str]): The refresh token from the HTTP-only cookie.
        token_data (dict): The decoded user info from the validated refresh token.

    Returns:
        SuccessResponse[TokenRefreshResponse]: A success message and new tokens.

    Raises:
        RefreshTokenExpired: If the refresh token is missing or invalid.
    """
    if not token_data:
        raise RefreshTokenExpired

    token_response = await build_refresh_response(request, response, token_data, refresh_cookie)

    return success_response(
        status_code=status.HTTP_200_OK,
        message="Token refreshed successfully",
        data=token_response
    )


@router.post("/logout", status_code=status.HTTP_200_OK, response_model=SuccessResponse[LogoutResponse])
async def logout(request: Request, token_data: dict = Depends(AccessTokenBearer())):
    """
    Log the user out by invalidating the access token.

    Adds the token's JTI to the Redis blocklist, effectively revoking it.

    Args:
        request (Request): FastAPI request object.
        token_data (dict): The decoded JWT token payload.

    Returns:
        JSONResponse with success message and deleted refresh token cookie.
    """
    jti = token_data.get("jti")
    await add_jti_to_blocklist(jti)

    logger.info("User with token jti %s has been logged out", jti)

    # Create the success response data
    response_data = success_response(
        status_code=status.HTTP_200_OK,
        message="User logged out Successfully",
        data=LogoutResponse()
    )

    # Create JSONResponse with the data (this preserves the schema)
    logout_response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=response_data.dict()
    )

    origin = request.headers.get("origin", "")
    domain = None if "localhost" in origin else settings.COOKIE_DOMAIN
    
    logout_response.delete_cookie(
        key="refresh_token",
        domain=domain,
        path="/"
    )

    return logout_response