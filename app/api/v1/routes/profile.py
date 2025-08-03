import logging
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.services.users import UserService
from app.api.core.dependencies.auth import AccessTokenBearer
from app.api.v1.schemas.users import UpdateUserRequest, UserResponse, DeleteUserResponse
from app.api.v1.schemas.sucess_response import SuccessResponse
from app.api.utils.success_response import success_response
from app.api.db.database import get_db
from app.api.exceptions.exceptions import UserNotFound, UserDeletionFailed
from app.api.core.dependencies.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users/me", tags=["profile"])


@router.get("", status_code=status.HTTP_200_OK, response_model=SuccessResponse[UserResponse])
async def get_user_profile(token_data: dict = Depends(AccessTokenBearer()), db: AsyncSession = Depends(get_db)):
    """
    Get current authenticated user profile.

    Retrieves user profile details using the email present in the access token.

    Args:
        token_data (dict): Decoded JWT token payload containing the user's email.

    Returns:
        Standard success response with UserResponse: Basic profile information of the authenticated user.

    Raises:
        UserNotFound: If no user is associated with the token email.
    """
    user = await UserService.get_user_by_email(token_data["user"]["email"], db)
    if not user:
        logger.warning("User not found for token email: %s", token_data["user"]["email"])
        raise UserNotFound()

    logger.info("Profile retrieved for user: %s", user.email)

    return success_response(
        status_code=status.HTTP_200_OK,
        message="User profile retrieved successfully",
        data=UserResponse.from_orm(user)
    )


@router.put(
    "",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse[UserResponse],
    dependencies=[Depends(rate_limiter(prefix="update_profile"))]
)
async def update_profile(
    update_data: UpdateUserRequest,
    token_data: dict = Depends(AccessTokenBearer()),
    db: AsyncSession = Depends(get_db)
):
    """
    Update current user's profile.

    This endpoint is rate-limited to prevent abuse of profile update operations.

    Args:
        update_data (UpdateUserRequest): Fields provided for update.
        token_data (dict): Decoded JWT token payload with user identification.

    Returns:
        Standard success response with UserResponse: The updated user profile.

    Raises:
        UserNotFound: If user is not found in the database.
    """
    user = await UserService.get_user_by_email(token_data["user"]["email"], db)
    if not user:
        logger.warning("User not found during update: %s", token_data["user"]["email"])
        raise UserNotFound()

    updated_user = await UserService.update_user(user, update_data.dict(exclude_unset=True), db)

    logger.info("User profile updated: %s", updated_user.email)

    return success_response(
        status_code=status.HTTP_200_OK,
        message="User profile updated successfully",
        data=UserResponse.from_orm(updated_user)
    )


@router.delete(
    "",
    status_code=status.HTTP_200_OK,
    response_model=SuccessResponse[DeleteUserResponse],
    dependencies=[Depends(rate_limiter(prefix="delete_profile"))]
)
async def delete_profile(token_data: dict = Depends(AccessTokenBearer()), db: AsyncSession = Depends(get_db)):
    """
    Delete the authenticated user's account.

    This endpoint is rate-limited to avoid repeated or automated account deletions.

    Args:
        token_data (dict): Decoded JWT token payload used to identify the user.

    Returns:
        Standard success response with DeleteUserResponse: A success message confirming account deletion.

    Raises:
        UserNotFound: If the user doesn't exist.
        UserDeletionFailed: If the deletion operation fails.
    """
    user = await UserService.get_user_by_email(token_data["user"]["email"], db)
    if not user:
        logger.warning("User not found for deletion: %s", token_data["user"]["email"])
        raise UserNotFound()

    success = await UserService.delete_user(user, db)
    if not success:
        logger.error("Failed to delete user: %s", user.email)
        raise UserDeletionFailed()

    logger.info("User account deleted: %s", user.email)

    return success_response(
        status_code=status.HTTP_200_OK,
        message="User account deleted successfully",
        data=DeleteUserResponse()
    )
