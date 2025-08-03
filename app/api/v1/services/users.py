import logging

from datetime import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.v1.models.users import User
from app.api.v1.schemas.auth import UserCreate
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
