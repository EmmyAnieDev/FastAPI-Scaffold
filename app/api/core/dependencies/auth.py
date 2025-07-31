from fastapi import Depends
from fastapi.security import HTTPBearer
from fastapi.requests import Request
from typing import List, Any

from app.api.db.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.models.users import User
from app.api.v1.services.users import UserService
from app.api.utils.token import decode_token
from app.api.core.redis import jti_in_blocklist
from app.api.exceptions.register import (
    AccessTokenRequired, RefreshTokenRequired, InvalidToken, RevokedToken,
    InsufficientPermission, UserNotFound, InvalidTokenPayload
)


class TokenBearer(HTTPBearer):
    """
    Base class for creating token-based authentication dependencies.

    This class uses HTTPBearer to extract the token and decode it. It performs:
    - Basic token validation
    - JTI (JWT ID) blacklist checks
    - Delegates token-type specific checks to subclasses via `verify_token_data`.

    Subclasses must override `verify_token_data` to define specific behavior for
    access vs. refresh tokens.
    """

    def __init__(self, auto_error=True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> dict:
        """
        Called by FastAPI to process the incoming request and return token data.

        Args:
            request (Request): The incoming HTTP request.

        Returns:
            dict: Decoded token payload.

        Raises:
            InvalidToken: If the token is invalid.
            RevokedToken: If the token has been blacklisted.
            AccessTokenRequired/RefreshTokenRequired: Based on subclass checks.
        """
        creds = await super().__call__(request)
        token = creds.credentials
        token_data = decode_token(token)

        if not self.token_valid(token):
            raise InvalidToken()

        if await jti_in_blocklist(token_data['jti']):
            raise RevokedToken()

        self.verify_token_data(token_data)

        return token_data


    @staticmethod
    def token_valid(token: str) -> bool:
        """
        Check if the token is valid (i.e., decodable and not empty).

        Args:
            token (str): The JWT token.

        Returns:
            bool: True if valid, False otherwise.
        """
        token_data = decode_token(token)
        return bool(token_data)


    @staticmethod
    def verify_token_data(token_data: dict) -> None:
        """
        Should be overridden in subclasses to check if token is access or refresh.

        Raises:
            NotImplementedError: If not overridden.
        """
        raise NotImplementedError("Please override this method in child classes.")


class AccessTokenBearer(TokenBearer):
    """
    Dependency that ensures the token is a valid access token.
    """
    @staticmethod
    def verify_token_data(token_data: dict) -> None:
        if token_data and token_data.get("refresh"):
            raise AccessTokenRequired()


class RefreshTokenBearer(TokenBearer):
    """
    Dependency that ensures the token is a valid refresh token.
    """
    @staticmethod
    def verify_token_data(token_data: dict) -> None:
        if token_data and not token_data.get("refresh"):
            raise RefreshTokenRequired()


async def get_current_user(
    token_details: dict = Depends(AccessTokenBearer()),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency to get the currently authenticated user from token details.

    Args:
        token_details (dict): Decoded JWT payload from AccessTokenBearer.
        db (AsyncSession): Database session for querying user.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: If user is not found or email is missing.
    """
    user_email = token_details['user'].get('email')

    if not user_email:
        raise InvalidTokenPayload()

    user = await UserService.get_user_by_email(email=user_email, db=db)

    if not user:
        raise UserNotFound()

    return user


class CheckRole:
    """
    Dependency that checks if the current user has an allowed role.

    Usage:
        Depends(CheckRole(["admin", "manager"]))

    Raises:
        AccountNotVerified: If the user's account is not verified.
        InsufficientPermission: If the user's role is not allowed.
    """

    def __init__(self, allowed_roles: List[str]) -> None:
        self.allowed_roles = allowed_roles

    async def __call__(self, current_user: User = Depends(get_current_user)) -> Any:
        """
        Called by FastAPI to check the user's role.

        Args:
            current_user (User): The current authenticated user.

        Returns:
            bool: True if user has permission.

        Raises:
            InsufficientPermission: If role is not in allowed roles.
        """

        if current_user.role in self.allowed_roles:
            return True

        raise InsufficientPermission()