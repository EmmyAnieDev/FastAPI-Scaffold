import logging
import random
import secrets
import time
from typing import Tuple, Optional
from config import settings

from app.api.core.redis import redis_client

logger = logging.getLogger(__name__)


async def generate_verification_session(email: str, purpose: str) -> Tuple[str, str]:
    """
    Generate a verification session (e.g., password reset, email verification).

    This function creates a secure session in Redis consisting of:
        - A unique verification token (secure, URL-safe, 64 characters).
        - A 4-digit one-time password (OTP).

    The session is tied to the provided email and a specific purpose 
    (e.g., "reset_password", "email_verification"). The session allows 
    the system to verify ownership of the email before proceeding with 
    sensitive operations. The session automatically expires after 
    `settings.VERIFICATION_SESSION_EXPIRY` seconds if the OTP is not verified.

    Args:
        email (str): The email address associated with the verification request.
        purpose (str): The type of verification being performed. 
                       Example values: "reset_password", "email_verification".

    Returns:
        Tuple[str, str]:
            - verification_token (str): The secure token identifying the session.
            - otp (str): The 4-digit OTP associated with this session.
    """
    try:
        verification_token = secrets.token_urlsafe(32)
        otp = f"{random.randint(1000, 9999)}"

        session_data = {
            "email": email,
            "otp": otp,
            "verified": "false",
            "purpose": purpose,
            "created_at": str(int(time.time())),
            "last_sent_at": str(int(time.time())),
            "resend_count": "0"  # Track number of OTP resends
        }

        session_key = f"verification_session:{purpose}:{verification_token}"
        await redis_client.hset(session_key, mapping=session_data)
        await redis_client.expire(session_key, settings.VERIFICATION_SESSION_EXPIRY)

        logger.info(
            "[VERIFICATION_SESSION_SAVED] purpose=%s email=%s token=%s otp=**** expiry=%ss",
            purpose,
            email,
            verification_token[:8] + "...",
            settings.VERIFICATION_SESSION_EXPIRY
        )

        return verification_token, otp

    except Exception as e:
        logger.error(
            "[VERIFICATION_SESSION_SAVE_FAILED] purpose=%s email=%s error=%s",
            purpose,
            email,
            str(e)
        )
        raise


async def verify_otp_and_mark_verified(purpose: str, verification_token: str, otp: str) -> bool:
    """
    Verify the OTP for a verification session and mark it as verified.
    To proceed with sensitive actions (e.g., password reset, email change),
    the user must provide the correct OTP sent to their email.

    If the provided OTP matches the one stored in Redis for the given purpose
    and verification token, the session is marked verified and its expiry is
    extended to `settings.VERIFIED_SESSION_EXPIRY`. to allow time to complete
    the intended action (e.g., reset password, change email).

    Args:
        purpose (str): The type of verification (e.g., "reset_password").
        verification_token (str): The token identifying the session.
        otp (str): The OTP provided by the user.

    Returns:
        bool: True if OTP is valid and session marked verified, False otherwise.
    """
    try:
        session_key = f"verification_session:{purpose}:{verification_token}"
        session_data = await redis_client.hgetall(session_key)

        if not session_data:
            logger.warning(
                "[VERIFICATION_SESSION_NOT_FOUND] purpose=%s token=%s",
                purpose,
                verification_token[:8] + "..."
            )
            return False

        if session_data.get("otp") != otp:
            logger.warning(
                "[VERIFICATION_SESSION_INVALID_OTP] purpose=%s token=%s provided_otp=**** expected_otp=***",
                purpose,
                verification_token[:8] + "..."
            )
            return False

        await redis_client.hset(session_key, "verified", "true")
        await redis_client.expire(session_key, settings.VERIFIED_SESSION_EXPIRY)

        logger.info(
            "[VERIFICATION_SESSION_VERIFIED] purpose=%s token=%s email=%s extended_expiry=%ss",
            purpose,
            verification_token[:8] + "...",
            session_data.get("email"),
            settings.VERIFIED_SESSION_EXPIRY,
        )
        return True

    except Exception as e:
        logger.error(
            "[VERIFICATION_SESSION_VERIFY_ERROR] purpose=%s token=%s error=%s",
            purpose,
            verification_token[:8] + "...",
            str(e)
        )
        return False


async def get_verified_session_email(purpose: str, verification_token: str) -> Optional[str]:
    """
    Retrieve the email associated with a verified session.

    Only returns an email if the session exists in Redis and has
    been marked as verified. Otherwise, returns None.

    Args:
        purpose (str): The type of verification (e.g., "reset_password").
        verification_token (str): The token identifying the session.

    Returns:
        Optional[str]: The email address if the session is verified, None otherwise.
    """
    try:
        session_key = f"verification_session:{purpose}:{verification_token}"
        session_data = await redis_client.hgetall(session_key)

        if not session_data:
            logger.warning(
                "[VERIFICATION_SESSION_NOT_FOUND] purpose=%s token=%s",
                purpose,
                verification_token[:8] + "..."
            )
            return None

        if session_data.get("verified") != "true":
            logger.warning(
                "[VERIFICATION_SESSION_NOT_VERIFIED] purpose=%s token=%s email=%s",
                purpose,
                verification_token[:8] + "...",
                session_data.get("email")
            )
            return None

        logger.info(
            "[VERIFICATION_SESSION_EMAIL_RETRIEVED] purpose=%s token=%s email=%s",
            purpose,
            verification_token[:8] + "...",
            session_data.get("email")
        )
        return session_data.get("email")

    except Exception as e:
        logger.error(
            "[VERIFICATION_SESSION_EMAIL_ERROR] purpose=%s token=%s error=%s",
            purpose,
            verification_token[:8] + "...",
            str(e)
        )
        return None


async def cleanup_verification_session(purpose: str, verification_token: str) -> None:
    """
    Delete a verification session from Redis.

    Usually called after the verification action is complete
    (e.g., password reset, email confirmed) to prevent reuse.

    Args:
        purpose (str): The type of verification (e.g., "reset_password").
        verification_token (str): The token identifying the session.
    """
    try:
        session_key = f"verification_session:{purpose}:{verification_token}"
        await redis_client.delete(session_key)
        logger.info(
            "[VERIFICATION_SESSION_CLEANED] purpose=%s token=%s",
            purpose,
            verification_token[:8] + "..."
        )
    except Exception as e:
        logger.error(
            "[VERIFICATION_SESSION_CLEANUP_ERROR] purpose=%s token=%s error=%s",
            purpose,
            verification_token[:8] + "...",
            str(e)
        )


async def can_resend(session_key: str) -> bool:
    """
    Check if OTP can be resent for a verification session.

    This function enforces a cooldown period (`RESEND_COOLDOWN_SECONDS`) between OTP resends
    and a maximum number of allowed resends (`MAX_RESENDS`). It checks the session data in Redis
    for the last sent timestamp and the resend count.

    Args:
        session_key (str): The Redis key for the verification session.

    Returns:
        bool: True if OTP can be resent, False otherwise.
    """
    try:
        session_data = await redis_client.hgetall(session_key)
        if not session_data:
            logger.warning(
                "[VERIFICATION_SESSION_CAN_RESEND_NOT_FOUND] session_key=%s",
                session_key[:20] + "..."
            )
            return False

        last_sent_at = session_data.get("last_sent_at")
        resend_count = int(session_data.get("resend_count", "0"))

        logger.debug(
            "[VERIFICATION_SESSION_CAN_RESEND_CHECK] session_key=%s last_sent_at=%s resend_count=%d",
            session_key[:20] + "...",
            last_sent_at,
            resend_count
        )

        now = int(time.time())

        # Cooldown check
        if last_sent_at and (now - int(last_sent_at)) < settings.RESEND_COOLDOWN_SECONDS:
            logger.info(
                "[VERIFICATION_SESSION_CAN_RESEND_COOLDOWN] session_key=%s last_sent_at=%s now=%s cooldown=%ss",
                session_key[:20] + "...",
                last_sent_at,
                now,
                settings.RESEND_COOLDOWN_SECONDS
            )
            return False

        # Max resend check
        if resend_count >= settings.MAX_RESENDS:
            logger.info(
                "[VERIFICATION_SESSION_CAN_RESEND_MAX_REACHED] session_key=%s resend_count=%d max_resends=%d",
                session_key[:20] + "...",
                resend_count,
                settings.MAX_RESENDS
            )
            return False

        logger.info(
            "[VERIFICATION_SESSION_CAN_RESEND_ALLOWED] session_key=%s resend_count=%d",
            session_key[:20] + "...",
            resend_count
        )
        return True
    except Exception as e:
        logger.error(
            "[VERIFICATION_SESSION_CAN_RESEND_ERROR] session_key=%s error=%s",
            session_key[:20] + "...",
            str(e)
        )
        return False


async def update_resend(session_key: str, new_otp: str) -> None:
    """
    Update the OTP and resend metadata for a verification session.

    This function updates the OTP, the last sent timestamp, and the resend count in Redis.
    It also resets the session expiry to `settings.VERIFICATION_SESSION_EXPIRY`.

    Args:
        session_key (str): The Redis key for the verification session.
        new_otp (str): The new OTP to set for the session.
    """
    try:
        now = int(time.time())
        session_data = await redis_client.hgetall(session_key)

        if not session_data:
            logger.warning(
                "[VERIFICATION_SESSION_UPDATE_RESEND_NOT_FOUND] session_key=%s",
                session_key[:20] + "..."
            )
            return

        resend_count = int(session_data.get("resend_count", "0"))

        await redis_client.hset(
            session_key,
            mapping={
                "otp": new_otp,
                "last_sent_at": str(now),
                "resend_count": str(resend_count + 1),
            },
        )
        await redis_client.expire(session_key, settings.VERIFICATION_SESSION_EXPIRY)

        logger.info(
            "[VERIFICATION_SESSION_RESEND_UPDATED] session_key=%s new_otp=**** resend_count=%d time=%s",
            session_key[:20] + "...",
            resend_count + 1,
            now
        )
    except Exception as e:
        logger.error(
            "[VERIFICATION_SESSION_UPDATE_RESEND_ERROR] session_key=%s error=%s",
            session_key[:20] + "...",
            str(e)
        )
