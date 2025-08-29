import logging
import random
import secrets
import time
from typing import Tuple, Optional
from config import settings

from app.api.core.redis import redis_client

logger = logging.getLogger(__name__)


async def generate_reset_session(email: str) -> Tuple[str, str]:
    """
    Generate a password reset session for the given email.

    This function creates a secure reset session in Redis consisting of:
        - A unique reset token (secure, URL-safe, 64 characters).
        - A 4-digit one-time password (OTP).

    The reset session allows the user to verify ownership of the email
    before resetting their password. The session expires after
    `settings.RESET_SESSION_EXPIRY` seconds if the OTP is not verified.

    Args:
        email (str): The email address associated with the reset request.

    Returns:
        Tuple[str, str]: A tuple containing:
            - reset_token (str): The secure token identifying the session.
            - otp (str): The 4-digit OTP associated with this session.

    Raises:
        Exception: If there is an error saving the reset session to Redis.
    """
    try:
        reset_token = secrets.token_urlsafe(32)
        otp = f"{random.randint(1000, 9999)}"

        reset_data = {
            "email": email,
            "otp": otp,
            "verified": "false",
            "created_at": str(int(time.time()))
        }

        reset_key = f"reset_session:{reset_token}"
        await redis_client.hset(reset_key, mapping=reset_data)
        await redis_client.expire(reset_key, settings.RESET_SESSION_EXPIRY)

        logger.info(
            "[RESET_SESSION_SAVED] email=%s token=%s otp=**** expiry=%ss",
            email,
            reset_token[:8] + "...",
            settings.RESET_SESSION_EXPIRY
        )

        return reset_token, otp

    except Exception as e:
        logger.error("[RESET_SESSION_SAVE_FAILED] email=%s error=%s", email, str(e))
        raise


async def verify_reset_otp_and_mark_verified(reset_token: str, otp: str) -> bool:
    """
    Verify the OTP for a reset session and mark it as verified.

    If the provided OTP matches the one stored in Redis, the session
    is marked as verified and its expiry is extended to
    `settings.VERIFIED_RESET_EXPIRY`. This allows the user additional
    time to submit a new password.

    Args:
        reset_token (str): The token identifying the reset session.
        otp (str): The OTP provided by the user.

    Returns:
        bool: True if OTP is valid and session is marked verified, False otherwise.

    Logging:
        Logs successful verification, invalid OTP attempts, and errors.
    """
    try:
        reset_key = f"reset_session:{reset_token}"
        reset_data = await redis_client.hgetall(reset_key)

        if not reset_data:
            logger.warning("[RESET_SESSION_NOT_FOUND] token=%s", reset_token[:8] + "...")
            return False

        if reset_data.get("otp") != otp:
            logger.warning(
                "[RESET_SESSION_INVALID_OTP] token=%s provided_otp=**** expected_otp=***",
                reset_token[:8] + "..."
            )
            return False

        await redis_client.hset(reset_key, "verified", "true")
        await redis_client.expire(reset_key, settings.VERIFIED_RESET_EXPIRY)

        logger.info(
            "[RESET_SESSION_VERIFIED] token=%s email=%s extended_expiry=%ss",
            reset_token[:8] + "...",
            reset_data.get("email"),
            settings.VERIFIED_RESET_EXPIRY,
        )
        return True

    except Exception as e:
        logger.error("[RESET_SESSION_VERIFY_ERROR] token=%s error=%s", reset_token[:8] + "...", str(e))
        return False


async def get_verified_reset_email(reset_token: str) -> Optional[str]:
    """
    Retrieve the email associated with a verified reset session.

    Only returns an email if the reset token exists in Redis and has
    been marked as verified. Otherwise, returns None.

    Args:
        reset_token (str): The token identifying the reset session.

    Returns:
        Optional[str]: The email address if the session is verified, None otherwise.

    Logging:
        Logs when token is not found, not verified, or when email is retrieved.
    """
    try:
        reset_key = f"reset_session:{reset_token}"
        reset_data = await redis_client.hgetall(reset_key)

        if not reset_data:
            logger.warning("[RESET_SESSION_NOT_FOUND] token=%s", reset_token[:8] + "...")
            return None

        if reset_data.get("verified") != "true":
            logger.warning("[RESET_SESSION_NOT_VERIFIED] token=%s email=%s", reset_token[:8] + "...", reset_data.get("email"))
            return None

        logger.info("[RESET_SESSION_EMAIL_RETRIEVED] token=%s email=%s", reset_token[:8] + "...", reset_data.get("email"))
        return reset_data.get("email")

    except Exception as e:
        logger.error("[RESET_SESSION_EMAIL_ERROR] token=%s error=%s", reset_token[:8] + "...", str(e))
        return None


async def cleanup_reset_session(reset_token: str) -> None:
    """
    Delete a reset session from Redis.

    This is usually called after the password has been successfully reset
    to prevent reuse of the token or OTP.

    Args:
        reset_token (str): The token identifying the reset session.

    Logging:
        Logs successful cleanup and any errors encountered.
    """
    try:
        reset_key = f"reset_session:{reset_token}"
        await redis_client.delete(reset_key)
        logger.info("[RESET_SESSION_CLEANED] token=%s", reset_token[:8] + "...")
    except Exception as e:
        logger.error("[RESET_SESSION_CLEANUP_ERROR] token=%s error=%s", reset_token[:8] + "...", str(e))
