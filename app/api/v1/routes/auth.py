import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, status, Depends, Request, Response, Cookie
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from app.api.v1.schemas.auth import (
    ConfirmResetPasswordSchema, ResendOtpSchema, ResetPasswordRequest, UserCreate,
    UserLogin, AuthResponse, TokenRefreshResponse, LogoutResponse, VerifyResetOtpSchema
)
from app.api.v1.schemas.sucess_response import SuccessResponse
from app.api.v1.services.users import UserService
from app.api.utils.success_response import success_response
from app.api.utils.token import verify_password
from app.api.utils.build_refresh_response import build_refresh_response
from app.api.utils.build_auth_response import build_auth_response
from app.api.exceptions.exceptions import (
    InvalidCredentials, InvalidToken, UserAlreadyExists, RefreshTokenExpired,
    RegistrationInitiationFailed,
)
from app.api.core.dependencies.auth import RefreshTokenBearer, AccessTokenBearer
from app.api.core.redis import add_jti_to_blocklist
from app.api.db.database import get_db
from app.api.core.dependencies.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=SuccessResponse[AuthResponse],
    dependencies=[Depends(rate_limiter(prefix="register"))]
)
async def register(
    user_data: UserCreate,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user.

    Rate limited to prevent automated or repeated abuse from the same IP.

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


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse[AuthResponse],
    dependencies=[Depends(rate_limiter(prefix="login"))]
)
async def login(
    data: UserLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and issue JWT tokens.

    This endpoint is rate-limited to prevent brute-force attempts.

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


@router.post(
    "/tokens/refresh",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse[TokenRefreshResponse],
    dependencies=[Depends(rate_limiter(prefix="refresh"))]
)
async def refresh_token(
    request: Request,
    response: Response,
    refresh_cookie: Optional[str] = Cookie(default=None),
    token_data: dict = Depends(RefreshTokenBearer())
):
    """
    Endpoint to refresh an expired or expiring access token using a refresh token.

    This endpoint is rate-limited to mitigate automated abuse.

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

    This route is not rate-limited because it doesn't pose significant risk
    if called repeatedly.

    Args:
        request (Request): FastAPI request object.
        token_data (dict): The decoded JWT token payload.

    Returns:
        JSONResponse with success message and deleted refresh token cookie.
    """
    jti = token_data.get("jti")
    await add_jti_to_blocklist(jti)

    logger.info("User with token jti %s has been logged out", jti)

    response_data = success_response(
        status_code=status.HTTP_200_OK,
        message="User logged out Successfully",
        data=LogoutResponse()
    )

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


@router.post(
    "/password/reset/requests",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    dependencies=[Depends(rate_limiter(prefix="reset_request", limit=3, window=3600))]
)
async def request_password_reset(
    data: ResetPasswordRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Initiate a password reset process by generating a one-time password (OTP)
    and a verification token, then sending the OTP to the user's email in the background.

    Args:
        data (ResetPasswordRequest): The email of the user requesting password reset.
        background_tasks (BackgroundTasks): FastAPI background tasks manager.
        db (AsyncSession): Asynchronous SQLAlchemy session.

    Returns:
        SuccessResponse: Success message with verification token for the next step.

    Raises:
        InvalidCredentials: If no user exists with the provided email.
    """
    user = await UserService.get_user_by_email(data.email, db)
    if not user:
        raise InvalidCredentials()
    
    verification_token = await UserService.initiate_password_reset(user, background_tasks)
    
    return success_response(
        status_code=status.HTTP_200_OK,
        message="Password reset OTP sent to your email",
        data={"verification_token": verification_token}
    )


@router.post(
    "/password/reset/resend",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    dependencies=[Depends(rate_limiter(prefix="reset_resend", limit=3, window=1800))]
)
async def resend_password_reset_otp(
    data: ResendOtpSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Resend password reset OTP.
    
    This endpoint allows users to request a new OTP if they didn't receive
    the original reset otp or if it expired.
    Users can only request a limited number of resends within a time period (1 minute cooldown, max 3 resends).

    Rate limited to 3 attempts per 30 minutes to prevent abuse.

    Args:
        data (ResendOtpSchema): Contains the verification token.
        background_tasks (BackgroundTasks): FastAPI background tasks manager.
        db (AsyncSession): Asynchronous SQLAlchemy session.

    Returns:
        Standard success response confirming OTP resend.

    Raises:
        InvalidToken: If the verification token is invalid or already verified.
    """
    logger.info("Resend password reset OTP requested for token: %s", data.verification_token[:8] + "...")

    success = await UserService.resend_password_reset_otp(data.verification_token, background_tasks, db)
    
    if not success:
        logger.warning("Failed to resend password reset OTP for token: %s", data.verification_token[:8] + "...")
        raise InvalidToken("Invalid or already verified token")

    logger.info("Password reset OTP resent successfully for token: %s", data.verification_token[:8] + "...")

    return success_response(
        status_code=status.HTTP_200_OK,
        message="Password reset code resent. Please check your email.",
        data=None
    )


@router.post(
    "/password/reset/verify",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    dependencies=[Depends(rate_limiter(prefix="reset_verify", limit=10, window=60))]
)
async def verify_reset_otp(data: VerifyResetOtpSchema):
    """
    Verify the OTP for password reset and mark the verification token as verified.

    Args:
        data (VerifyResetOtpSchema): The verification token and OTP.

    Returns:
        SuccessResponse: Success message confirming OTP verification.

    Raises:
        InvalidToken: If the verification token or OTP is invalid.
    """
    is_verified = await UserService.verify_reset_otp(data)
    if not is_verified:
        raise InvalidToken()

    return success_response(
        status_code=status.HTTP_200_OK,
        message="OTP verified successfully. You can now reset your password.",
        data=None
    )


@router.post(
    "/password/reset/confirm",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse,
    dependencies=[Depends(rate_limiter(prefix="reset_confirm", limit=5, window=600))]
)
async def confirm_password_reset(
    data: ConfirmResetPasswordSchema,
    db: AsyncSession = Depends(get_db)
):
    """
    Complete the password reset process using a verified verification token.

    Args:
        data (ConfirmResetPasswordSchema): The verified verification token and new password.
        db (AsyncSession): Asynchronous SQLAlchemy session.

    Returns:
        SuccessResponse[ResetPasswordResponse]: Success message confirming password reset.

    Raises:
        InvalidToken: If the verification token is not verified or expired.
    """
    user = await UserService.confirm_password_reset(data, db)
    if not user:
        raise InvalidToken()

    return success_response(
        status_code=status.HTTP_200_OK,
        message="Password reset successfully",
        data=None
    )
