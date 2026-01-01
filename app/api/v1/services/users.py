import logging

from datetime import datetime
from typing import Optional
from fastapi import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.core.redis import redis_client
from config import settings
from app.api.utils.verification_otp_token import can_resend, generate_verification_session, update_resend, verify_otp_and_mark_verified, get_verified_session_email, cleanup_verification_session   
from app.api.utils.send_email import send_email
from app.api.v1.models.users import User
from app.api.v1.schemas.auth import ConfirmResetPasswordSchema, UserCreate, VerifyResetOtpSchema
from app.api.utils.token import generate_password_hash

logger = logging.getLogger(__name__)


class UserService:
    """
    Service class for user-related operations.
    """

    @staticmethod
    async def get_user_by_email(email: str, db: AsyncSession) -> Optional[User]:
        """
        Retrieve a user by their email.

        Args:
            email (str): The email to search for.
            db (AsyncSession): Async SQLAlchemy session.

        Returns:
            Optional[User]: The user object if found, else None.
        """
        try:
            result = await db.execute(select(User).where(User.email == email))
            user = result.scalars().first()
            logger.info("Fetched user by email: %s", email)
            return user
        except Exception as e:
            logger.error("Error fetching user by email %s: %s", email, str(e))
            return None
        

    @staticmethod
    async def user_exists(email: str, db: AsyncSession) -> bool:
        """
        Check if a user exists by email.

        Args:
            email (str): Email to check.
            db (AsyncSession): Async SQLAlchemy session.

        Returns:
            bool: True if user exists, False otherwise.
        """
        user = await UserService.get_user_by_email(email, db)
        return user is not None
    

    @staticmethod
    async def register_user(user_data: UserCreate, db: AsyncSession) -> Optional[User]:
        """
        Registers a new user with either email/password or a third-party provider (e.g., Google).

        For 'email' provider:
            - Password is required and will be hashed before storing.
        
        For third-party providers (e.g., 'google'):
            - Password is not required and will be set to None.

        Args:
            user_data (UserCreate): The user registration data, including email, password (if email-based), and provider.
            db (AsyncSession): The async database session.

        Returns:
            Optional[User]: The newly created User object if registration is successful; otherwise, None.
        """
        try:
            logger.info("Registering user with email: %s", user_data.email)

            if await UserService.user_exists(user_data.email, db):
                logger.warning("Registration attempted for existing user: %s", user_data.email)
                return None

            provider = getattr(user_data, "provider", "email")

            if provider == "email":
                if not user_data.password:
                    logger.warning("Email provider requires a password.")
                    return None
                hashed_password = generate_password_hash(user_data.password)
            else:
                # For Google and other OAuth providers, skip password
                hashed_password = None

            user = User(
                email=user_data.email,
                password_hash=hashed_password,
                provider=provider
            )

            await user.save(db)

            logger.info("User registered successfully: %s", user.email)
            return user

        except Exception as e:
            await db.rollback()
            logger.error("Failed to register user %s: %s", user_data.email, str(e))
            return None

    
    @staticmethod
    async def update_user(user: User, update_data: dict, db: AsyncSession) -> User:
        """
        Update an existing user's information.

        Args:
            user (User): User instance to update.
            update_data (dict): Dictionary of updated fields.
            db (AsyncSession): Async SQLAlchemy session.

        Returns:
            User: The updated user object.
        """
        try:
            for key, value in update_data.items():
                setattr(user, key, value)

            user.updated_at = datetime.utcnow()
            await user.save(db)

            logger.info("User updated successfully: %s", user.email)
            return user

        except Exception as e:
            await db.rollback()
            logger.error("Error updating user %s: %s", user.email, str(e))
            raise
        

    @staticmethod
    async def delete_user(user: User, db: AsyncSession) -> bool:
        """
        Delete a user from the database.

        Args:
            user (User): The user instance to delete.
            db (AsyncSession): Async SQLAlchemy session.

        Returns:
            bool: True if deleted, False otherwise.
        """
        try:
            await user.delete(db)
            logger.info("User deleted successfully: %s", user.email)
            return True

        except Exception as e:
            await db.rollback()
            logger.error("Error deleting user %s: %s", user.email, str(e))
            return False
        
        
    @staticmethod
    async def initiate_password_reset(user: User, background_tasks: BackgroundTasks) -> str:
        """
        Generate a verification token and OTP for password reset, store them in Redis,
        and schedule OTP email sending as a background task.

        Args:
            user (User): The user requesting a password reset.
            background_tasks (BackgroundTasks): FastAPI background tasks manager.

        Returns:
            str: The verification token to be used in subsequent steps.

        Raises:
            Exception: If an error occurs during token/OTP generation.
        """
        try:
            # Generate verification token and OTP
            verification_token, otp = await generate_verification_session(user.email, purpose="reset_password")
            
            # Prepare email context
            email_context = {
                "email": user.email,
                "verification_code": otp,
                "verification_expiry": settings.VERIFICATION_SESSION_EXPIRY // 60, # in minutes
                "verified_expiry": settings.VERIFIED_SESSION_EXPIRY // 60, # in minutes
            }
            
            # Schedule email sending as background task
            background_tasks.add_task(
                send_email,
                recipients=[user.email],
                template_name="password_reset.html",
                subject="Reset Your Password",
                context=email_context
            )
            
            logger.info("Reset session created for %s, email queued", user.email)
            return verification_token
            
        except Exception as e:
            logger.error("Error initiating password reset for %s: %s", user.email, str(e))
            raise

    
    @staticmethod
    async def resend_password_reset_otp(verification_token: str, background_tasks: BackgroundTasks, db: AsyncSession) -> bool:
        """
        Resend password reset OTP for an existing unverified reset session.

        Args:
            verification_token (str): The verification token from initial reset request.
            background_tasks (BackgroundTasks): FastAPI background tasks manager.
            db (AsyncSession): Asynchronous SQLAlchemy session.

        Returns:
            bool: True if OTP resent successfully, False otherwise.
        """
        try:
            session_key = f"verification_session:reset_password:{verification_token}"
            session_data = await redis_client.hgetall(session_key)

            # Check if session exists
            if not session_data:
                logger.warning("Reset session not found for resend: %s", verification_token[:8] + "...")
                return False

            # Check if already verified
            if session_data.get("verified") == "true":
                logger.warning("Cannot resend OTP for already verified reset session: %s", verification_token[:8] + "...")
                return False

            # Check purpose
            if session_data.get("purpose") != "reset_password":
                logger.warning("Invalid purpose for password reset resend: %s", verification_token[:8] + "...")
                return False

            # Check resend cooldown and max attempts
            if not await can_resend(session_key):
                logger.warning("Resend blocked by cooldown or max attempts for reset token: %s", verification_token[:8] + "...")
                return False

            email = session_data.get("email")
            if not email:
                logger.error("No email found in reset session for resend: %s", verification_token[:8] + "...")
                return False

            # Verify user still exists in database
            user = await UserService.get_user_by_email(email, db)
            if not user:
                logger.warning("User no longer exists for password reset resend: %s", email)
                return False

            # Generate new OTP
            new_otp = f"{random.randint(1000, 9999)}"
            await update_resend(session_key, new_otp)
            
            # Update session with new OTP and reset expiry
            await redis_client.hset(session_key, "otp", new_otp)
            await redis_client.expire(session_key, settings.VERIFICATION_SESSION_EXPIRY)

            # Prepare email context
            email_context = {
                "email": email,
                "verification_code": new_otp,
                "verification_expiry": settings.VERIFICATION_SESSION_EXPIRY // 60, # in minutes
                "verified_expiry": settings.VERIFIED_SESSION_EXPIRY // 60, # in minutes
            }

            # Schedule email sending as background task
            background_tasks.add_task(
                send_email,
                recipients=[email],
                template_name="password_reset.html",
                subject="Reset Your Password",
                context=email_context
            )

            logger.info("Password reset OTP resent for %s", email)
            return True

        except Exception as e:
            logger.error("Error resending password reset OTP: %s", str(e))
            return False


    @staticmethod
    async def verify_reset_otp(data: VerifyResetOtpSchema) -> bool:
        """
        Verify the OTP for a verification token and mark the token as verified.

        Args:
            data (VerifyResetOtpSchema): Schema containing verification token and OTP.

        Returns:
            bool: True if OTP is verified and token marked as verified, False otherwise.
        """
        try:
            return await verify_otp_and_mark_verified(
                purpose="reset_password",
                verification_token=data.verification_token,
                otp=data.otp
            )
        except Exception as e:
            logger.error("Error verifying reset OTP: %s", str(e))
            return False


    @staticmethod
    async def confirm_password_reset(data: ConfirmResetPasswordSchema, db: AsyncSession) -> Optional[User]:
        """
        Complete password reset using a verified verification token.

        Args:
            data (ConfirmResetPasswordSchema): Schema containing verified verification token and new password.
            db (AsyncSession): Asynchronous SQLAlchemy session.

        Returns:
            Optional[User]: The updated user object if reset succeeds, else None.

        Raises:
            Exception: If token verification fails or database update encounters an error.
        """
        try:
            # Check if verification token is verified and get email
            email = await get_verified_session_email(purpose="reset_password", verification_token=data.verification_token)
            if not email:
                return None

            user = await UserService.get_user_by_email(email, db)
            if not user:
                return None

            # Update password
            hashed_password = generate_password_hash(data.new_password)
            user.password_hash = hashed_password
            user.updated_at = datetime.utcnow()

            await user.save(db)

            # Clean up the reset session
            await cleanup_verification_session(purpose="reset_password", verification_token=data.verification_token)

            logger.info("Password reset successful for user: %s", user.email)
            return user

        except Exception as e:
            await db.rollback()
            logger.error("Failed password reset: %s", str(e))
            return None
