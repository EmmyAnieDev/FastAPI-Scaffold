import logging
import uuid
from datetime import timedelta, datetime, timezone
from typing import Optional

import jwt
from passlib.context import CryptContext

from config import settings

logger = logging.getLogger(__name__)

password_context = CryptContext(schemes=["bcrypt"])


def generate_password_hash(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    Args:
        password (str): The plaintext password.

    Returns:
        str: The hashed password.
    """
    return password_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a hashed password.

    Args:
        password (str): The plaintext password.
        hashed_password (str): The hashed password.

    Returns:
        bool: True if the password matches, else False.
    """
    return password_context.verify(password, hashed_password)


async def create_access_token(
    user_data: dict,
    expiry: Optional[timedelta] = None,
    refresh: bool = False
) -> str:
    """
    Create a JWT access or refresh token.

    Args:
        user_data (dict): User information to encode into the token.
        expiry (Optional[timedelta]): Custom token expiry. Defaults to ACCESS_TOKEN_EXPIRY.
        refresh (bool): If True, marks the token as a refresh token.

    Returns:
        str: Encoded JWT token.
    """
    payload = {
        "user": user_data,
        "exp": datetime.now(timezone.utc) + (expiry if expiry else timedelta(seconds=settings.ACCESS_TOKEN_EXPIRY)),
        "jti": str(uuid.uuid4()),
        "refresh": refresh
    }

    token = jwt.encode(
        algorithm=settings.JWT_ALGORITHM,
        payload=payload,
        key=settings.JWT_SECRET
    )

    return token


def decode_token(token: str) -> dict:
    """
    Decode a JWT token.

    Args:
        token (str): The JWT token to decode.

    Returns:
        dict: The decoded token payload, or empty dict if invalid.
    """
    try:
        return jwt.decode(
            algorithms=[settings.JWT_ALGORITHM],
            jwt=token,
            key=settings.JWT_SECRET
        )
    except jwt.PyJWTError as e:
        logger.exception("Failed to decode token: %s", str(e))
        return {}
