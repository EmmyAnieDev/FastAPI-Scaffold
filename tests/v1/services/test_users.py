import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.api.v1.models.users import User
from app.api.v1.schemas.auth import UserCreate
from app.api.v1.services.users import UserService


@pytest.mark.asyncio
async def test_get_user_by_email_found(mock_db_session):
    mock_user = User(email="test@example.com")
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = mock_user
    mock_db_session.execute.return_value = mock_result

    user = await UserService.get_user_by_email("test@example.com", mock_db_session)
    assert user.email == "test@example.com"


@pytest.mark.asyncio
async def test_get_user_by_email_not_found(mock_db_session):
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_db_session.execute.return_value = mock_result

    user = await UserService.get_user_by_email("unknown@example.com", mock_db_session)
    assert user is None


@pytest.mark.asyncio
async def test_user_exists_true(mock_db_session):
    with patch.object(UserService, 'get_user_by_email', return_value=User(email="exists@example.com")):
        result = await UserService.user_exists("exists@example.com", mock_db_session)
        assert result is True


@pytest.mark.asyncio
async def test_user_exists_false(mock_db_session):
    with patch.object(UserService, 'get_user_by_email', return_value=None):
        result = await UserService.user_exists("notfound@example.com", mock_db_session)
        assert result is False


@pytest.mark.asyncio
async def test_register_user_success(mock_db_session):
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
    user_data = UserCreate(email="exist@example.com", password="password")

    with patch.object(UserService, 'user_exists', return_value=True):
        result = await UserService.register_user(user_data, mock_db_session)
        assert result is None


@pytest.mark.asyncio
async def test_update_user_success(mock_db_session):
    user = User(email="old@example.com", password_hash="oldpass")
    update_data = {"email": "new@example.com"}

    with patch("app.api.v1.models.users.User.save", new_callable=AsyncMock) as mock_save:
        updated_user = await UserService.update_user(user, update_data, mock_db_session)

        assert updated_user.email == "new@example.com"
        assert hasattr(updated_user, "updated_at")
        mock_save.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_user_success(mock_db_session):
    user = User(email="delete@example.com")

    with patch("app.api.v1.models.users.User.delete", new_callable=AsyncMock) as mock_delete:
        result = await UserService.delete_user(user, mock_db_session)
        assert result is True
        mock_delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_user_failure(mock_db_session):
    user = User(email="fail@example.com")

    with patch("app.api.v1.models.users.User.delete", side_effect=Exception("DB Error")):
        result = await UserService.delete_user(user, mock_db_session)
        assert result is False
        mock_db_session.rollback.assert_awaited_once()
