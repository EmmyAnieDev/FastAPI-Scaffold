from fastapi import BackgroundTasks
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.api.v1.models.users import User
from app.api.v1.schemas.auth import UserCreate
from app.api.v1.services.users import UserService


@pytest.mark.asyncio
async def test_get_user_by_email_found(mock_db_session):
    """
    Test retrieving an existing user by email.
    """
    mock_user = User(email="test@example.com")
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = mock_user
    mock_db_session.execute.return_value = mock_result

    user = await UserService.get_user_by_email("test@example.com", mock_db_session)
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_by_email_not_found(mock_db_session):
    """
    Test retrieving a non-existing user by email returns None.
    """
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_db_session.execute.return_value = mock_result

    user = await UserService.get_user_by_email("unknown@example.com", mock_db_session)
    assert user is None


@pytest.mark.asyncio
async def test_user_exists_true(mock_db_session):
    """
    Test user existence returns True when user is found.
    """
    with patch.object(UserService, 'get_user_by_email', return_value=User(email="exists@example.com")):
        result = await UserService.user_exists("exists@example.com", mock_db_session)
        assert result is True


@pytest.mark.asyncio
async def test_user_exists_false(mock_db_session):
    """
    Test user existence returns False when user is not found.
    """
    with patch.object(UserService, 'get_user_by_email', return_value=None):
        result = await UserService.user_exists("notfound@example.com", mock_db_session)
        assert result is False


@pytest.mark.asyncio
async def test_register_user_success(mock_db_session):
    """
    Test successful user registration with password hashing.
    """
    user_data = UserCreate(email="new@example.com", password="securepass")

    with patch.object(UserService, 'user_exists', return_value=False), \
         patch("app.api.v1.services.users.generate_password_hash", return_value="hashed_pw"), \
         patch("app.api.v1.models.users.User.save", new_callable=AsyncMock) as mock_save:

        result = await UserService.register_user(user_data, mock_db_session)
        assert result.email == user_data.email
        assert result.password_hash == "hashed_pw"
        mock_save.assert_awaited_once()


@pytest.mark.asyncio
async def test_register_user_already_exists(mock_db_session):
    """
    Test user registration fails when user already exists.
    """
    user_data = UserCreate(email="exist@example.com", password="password")

    with patch.object(UserService, 'user_exists', return_value=True):
        result = await UserService.register_user(user_data, mock_db_session)
        assert result is None


@pytest.mark.asyncio
async def test_update_user_success(mock_db_session):
    """
    Test successful user update.
    """
    user = User(email="old@example.com", password_hash="oldpass")
    update_data = {"email": "new@example.com"}

    with patch("app.api.v1.models.users.User.save", new_callable=AsyncMock) as mock_save:
        updated_user = await UserService.update_user(user, update_data, mock_db_session)

        assert updated_user.email == "new@example.com"
        assert hasattr(updated_user, "updated_at")
        mock_save.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_user_success(mock_db_session):
    """
    Test successful user deletion.
    """
    user = User(email="delete@example.com")

    with patch("app.api.v1.models.users.User.delete", new_callable=AsyncMock) as mock_delete:
        result = await UserService.delete_user(user, mock_db_session)
        assert result is True
        mock_delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_user_failure(mock_db_session):
    """
    Test user deletion failure with rollback.
    """
    user = User(email="fail@example.com")

    with patch("app.api.v1.models.users.User.delete", side_effect=Exception("DB Error")):
        result = await UserService.delete_user(user, mock_db_session)
        assert result is False
        mock_db_session.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_register_user_google_success(mock_db_session):
    """
    Test successful Google user registration without password.
    """
    user_data = UserCreate(email="googleuser@example.com", provider="google")

    with patch.object(UserService, 'user_exists', return_value=False), \
         patch("app.api.v1.models.users.User.save", new_callable=AsyncMock) as mock_save:

        result = await UserService.register_user(user_data, mock_db_session)
        assert result.email == user_data.email
        assert result.password_hash is None
        assert result.provider == "google"
        mock_save.assert_awaited_once()


@pytest.mark.asyncio
async def test_register_user_missing_password_email_provider(mock_db_session):
    """
    Test registration fails if password is missing for email provider.
    """
    user_data = UserCreate(email="no-pass@example.com", provider="email")

    with patch.object(UserService, 'user_exists', return_value=False):
        result = await UserService.register_user(user_data, mock_db_session)
        assert result is None


@pytest.mark.asyncio
async def test_initiate_password_reset_success():
    mock_user = User(email="user@example.com")
    background_tasks = BackgroundTasks()

    with patch("app.api.v1.services.users.generate_reset_session", return_value=("token123", "1234")), \
         patch("app.api.v1.services.users.send_email", new_callable=AsyncMock) as mock_send_email:

        token = await UserService.initiate_password_reset(mock_user, background_tasks)
        assert token == "token123"

        assert len(background_tasks.tasks) == 1
        task = background_tasks.tasks[0]
        assert task.func == mock_send_email
        assert task.kwargs["recipients"] == [mock_user.email]


@pytest.mark.asyncio
async def test_initiate_password_reset_failure():
    mock_user = User(email="fail@example.com")
    background_tasks = BackgroundTasks()

    with patch("app.api.v1.services.users.generate_reset_session", return_value=("token123", "1234")), \
         patch("app.api.v1.services.users.send_email", new_callable=AsyncMock, side_effect=Exception("SMTP fail")):

        token = await UserService.initiate_password_reset(mock_user, background_tasks)
        assert token == "token123"

        task = background_tasks.tasks[0]
        with pytest.raises(Exception) as exc_info:
            await task.func(*task.args, **task.kwargs)
        assert str(exc_info.value) == "SMTP fail"


@pytest.mark.asyncio
async def test_verify_reset_otp_success():
    """
    Test that verify_reset_otp returns True when OTP is valid.
    """
    mock_data = MagicMock()
    mock_data.reset_token = "token123"
    mock_data.otp = "1234"

    with patch("app.api.v1.services.users.verify_reset_otp_and_mark_verified", return_value=True):
        result = await UserService.verify_reset_otp(mock_data)
        assert result is True


@pytest.mark.asyncio
async def test_verify_reset_otp_failure():
    """
    Test that verify_reset_otp returns False when OTP verification fails.
    """
    mock_data = MagicMock()
    mock_data.reset_token = "token123"
    mock_data.otp = "9999"

    with patch("app.api.v1.services.users.verify_reset_otp_and_mark_verified", return_value=False):
        result = await UserService.verify_reset_otp(mock_data)
        assert result is False


@pytest.mark.asyncio
async def test_confirm_password_reset_success(mock_db_session):
    """
    Test that confirm_password_reset updates the user's password and cleans up the reset session.
    """
    data = MagicMock()
    data.reset_token = "token123"
    data.new_password = "newpass"

    mock_user = User(email="user@example.com", password_hash="oldpass")
    with patch("app.api.v1.services.users.get_verified_reset_email", return_value="user@example.com"), \
         patch.object(UserService, "get_user_by_email", return_value=mock_user), \
         patch("app.api.v1.services.users.generate_password_hash", return_value="hashedpass"), \
         patch("app.api.utils.reset_password_otp_token.cleanup_reset_session", new_callable=AsyncMock):

        updated_user = await UserService.confirm_password_reset(data, mock_db_session)
        assert updated_user.password_hash == "hashedpass"


@pytest.mark.asyncio
async def test_confirm_password_reset_invalid_token(mock_db_session):
    """
    Test that confirm_password_reset returns None if reset token is not verified.
    """
    data = MagicMock()
    data.reset_token = "token123"
    data.new_password = "newpass"

    with patch("app.api.v1.services.users.get_verified_reset_email", return_value=None):
        result = await UserService.confirm_password_reset(data, mock_db_session)
        assert result is None


@pytest.mark.asyncio
async def test_confirm_password_reset_user_not_found(mock_db_session):
    """
    Test that confirm_password_reset returns None if user associated with token does not exist.
    """
    data = MagicMock()
    data.reset_token = "token123"
    data.new_password = "newpass"

    with patch("app.api.v1.services.users.get_verified_reset_email", return_value="user@example.com"), \
         patch.object(UserService, "get_user_by_email", return_value=None):

        result = await UserService.confirm_password_reset(data, mock_db_session)
        assert result is None
