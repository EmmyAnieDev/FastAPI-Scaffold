import pytest
from unittest.mock import AsyncMock, patch
from app.api.utils import reset_password_otp_token

@pytest.mark.asyncio
async def test_generate_reset_session_success():
    """
    Test that generate_reset_session successfully creates a reset token and OTP,
    stores them in Redis, and returns them.
    """
    email = "user@example.com"

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hset = AsyncMock()
        mock_redis.expire = AsyncMock()

        token, otp = await reset_password_otp_token.generate_reset_session(email)

        assert isinstance(token, str)
        assert len(token) > 0
        assert otp.isdigit() and len(otp) == 4
        mock_redis.hset.assert_called_once()
        mock_redis.expire.assert_called_once()


@pytest.mark.asyncio
async def test_generate_reset_session_failure():
    """
    Test that generate_reset_session raises an exception when Redis fails to store the session.
    """
    email = "user@example.com"

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hset = AsyncMock(side_effect=Exception("Redis down"))
        mock_redis.expire = AsyncMock()

        with pytest.raises(Exception) as exc_info:
            await reset_password_otp_token.generate_reset_session(email)
        assert str(exc_info.value) == "Redis down"


@pytest.mark.asyncio
async def test_verify_reset_otp_and_mark_verified_success():
    """
    Test that verify_reset_otp_and_mark_verified returns True when OTP matches
    and updates the session as verified in Redis.
    """
    token = "reset-token"
    otp = "1234"
    mock_data = {"email": "user@example.com", "otp": otp, "verified": "false"}

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        mock_redis.hset = AsyncMock()
        mock_redis.expire = AsyncMock()

        result = await reset_password_otp_token.verify_reset_otp_and_mark_verified(token, otp)
        assert result is True
        mock_redis.hset.assert_called_once_with(f"reset_session:{token}", "verified", "true")
        mock_redis.expire.assert_called_once()


@pytest.mark.asyncio
async def test_verify_reset_otp_and_mark_verified_invalid_otp():
    """
    Test that verify_reset_otp_and_mark_verified returns False when OTP does not match.
    """
    token = "reset-token"
    otp = "9999"
    mock_data = {"email": "user@example.com", "otp": "1234", "verified": "false"}

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        result = await reset_password_otp_token.verify_reset_otp_and_mark_verified(token, otp)
        assert result is False


@pytest.mark.asyncio
async def test_verify_reset_otp_and_mark_verified_no_session():
    """
    Test that verify_reset_otp_and_mark_verified returns False when session does not exist in Redis.
    """
    token = "reset-token"
    otp = "1234"

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value={})
        result = await reset_password_otp_token.verify_reset_otp_and_mark_verified(token, otp)
        assert result is False


@pytest.mark.asyncio
async def test_get_verified_reset_email_success():
    """
    Test that get_verified_reset_email returns the correct email
    when the session exists and is verified.
    """
    token = "reset-token"
    mock_data = {"email": "user@example.com", "verified": "true"}

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        email = await reset_password_otp_token.get_verified_reset_email(token)
        assert email == "user@example.com"


@pytest.mark.asyncio
async def test_get_verified_reset_email_not_verified():
    """
    Test that get_verified_reset_email returns None when the session exists but is not verified.
    """
    token = "reset-token"
    mock_data = {"email": "user@example.com", "verified": "false"}

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        email = await reset_password_otp_token.get_verified_reset_email(token)
        assert email is None


@pytest.mark.asyncio
async def test_get_verified_reset_email_no_session():
    """
    Test that get_verified_reset_email returns None when the session does not exist.
    """
    token = "reset-token"

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value={})
        email = await reset_password_otp_token.get_verified_reset_email(token)
        assert email is None


@pytest.mark.asyncio
async def test_cleanup_reset_session_success():
    """
    Test that cleanup_reset_session deletes the session from Redis successfully.
    """
    token = "reset-token"

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.delete = AsyncMock()
        await reset_password_otp_token.cleanup_reset_session(token)
        mock_redis.delete.assert_called_once_with(f"reset_session:{token}")
        

@pytest.mark.asyncio
async def test_cleanup_reset_session_failure():
    """
    Test that cleanup_reset_session handles Redis deletion failure gracefully.
    """
    token = "reset-token"

    with patch("app.api.utils.reset_password_otp_token.redis_client") as mock_redis:
        mock_redis.delete = AsyncMock(side_effect=Exception("Redis down"))
        await reset_password_otp_token.cleanup_reset_session(token)
