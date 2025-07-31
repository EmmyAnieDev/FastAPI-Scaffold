import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from app.api.v1.schemas.auth import UserCreate, UserLogin, AuthResponse
from app.api.v1.schemas.sucess_response import SuccessResponse
from app.api.v1.services.users import UserService
from app.api.utils.success_response import success_response
from app.api.utils.token import verify_password, create_access_token
from app.api.exceptions.exceptions import (
    InvalidCredentials, UserAlreadyExists, RefreshTokenExpired,
    RegistrationInitiationFailed,
)
from app.api.core.dependencies.auth import RefreshTokenBearer, AccessTokenBearer
from app.api.core.redis import add_jti_to_blocklist
from app.api.db.database import get_db
from app.api.v1.schemas.auth import TokenRefreshResponse, LogoutResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=SuccessResponse[AuthResponse])
async def Register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user.

    Args:
        user_data (UserCreate): New user registration details.
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

    access_token = await create_access_token({"id": str(user.id), "email": user.email})
    refresh_token = await create_access_token(
        {"id": str(user.id), "email": user.email},
        refresh=True,
        expiry=timedelta(days=settings.REFRESH_TOKEN_EXPIRY)
    )

    logger.info("Tokens generated for user: %s", user.email)

    response_data = AuthResponse(
        id=str(user.id),
        email=user.email,
        created_at=user.created_at,
        access_token=access_token,
        refresh_token=refresh_token,
    )

    return success_response(
        status_code=status.HTTP_201_CREATED,
        message="User Registered Successfully",
        data=response_data,
    )


@router.post("/login", status_code=status.HTTP_200_OK, response_model=SuccessResponse[AuthResponse])
async def login(
    data: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and issue JWT tokens.

    This endpoint verifies the user's email and password. If valid,
    it returns access and refresh tokens.

    Args:
        data (UserLogin): Login credentials.
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

    access_token = await create_access_token({"id": str(user.id), "email": user.email})
    refresh_token = await create_access_token(
        {"id": str(user.id), "email": user.email},
        refresh=True,
        expiry=timedelta(days=settings.REFRESH_TOKEN_EXPIRY)
    )

    logger.info("Tokens generated for user: %s", user.email)
    
    response_data = AuthResponse(
        id=str(user.id),
        email=user.email,
        created_at=user.created_at,
        access_token=access_token,
        refresh_token=refresh_token,
    )

    return success_response(
        status_code=status.HTTP_200_OK,
        message="User logged in Successfully",
        data=response_data,
    )


@router.post("/tokens/refresh", status_code=status.HTTP_200_OK, response_model=SuccessResponse[TokenRefreshResponse])
async def refresh_token(token_data: dict = Depends(RefreshTokenBearer())):
    """
    Refresh access and refresh tokens.

    Validates the refresh token and issues new access and refresh tokens.

    Args:
        token_data (dict): The JWT payload of a valid refresh token.

    Returns:
        Standard success response with TokenRefreshResponse and new tokens.

    Raises:
        RefreshTokenExpired: If the refresh token is expired.
    """
    expiry = token_data['exp']
    if datetime.fromtimestamp(expiry) <= datetime.utcnow():
        logger.warning("Refresh token expired for user: %s", token_data['user']['email'])
        raise RefreshTokenExpired()

    user = token_data['user']
    payload = {"id": str(user['id']), "email": user['email']}

    new_access_token = await create_access_token(payload)
    new_refresh_token = await create_access_token(
        payload,
        refresh=True,
        expiry=timedelta(days=settings.REFRESH_TOKEN_EXPIRY)
    )

    logger.info("Tokens refreshed for user: %s", user['email'])

    response_data =  TokenRefreshResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token
    )

    return success_response(
        status_code=status.HTTP_200_OK,
        message="Token refreshed Successfully",
        data=response_data,
    )


@router.post("/logout", status_code=status.HTTP_200_OK, response_model=SuccessResponse[LogoutResponse])
async def logout(token_data: dict = Depends(AccessTokenBearer())):
    """
    Log the user out by invalidating the access token.

    Adds the token's JTI to the Redis blocklist, effectively revoking it.

    Args:
        token_data (dict): The decoded JWT token payload.

    Returns:
        Standard success response with message indicating logout was successful.
    """
    jti = token_data.get("jti")
    await add_jti_to_blocklist(jti)

    logger.info("User with token jti %s has been logged out", jti)

    return success_response(
        status_code=status.HTTP_200_OK,
        message="User logged out Successfully",
        data=LogoutResponse()
    )
