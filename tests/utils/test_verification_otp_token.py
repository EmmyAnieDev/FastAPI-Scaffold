import pytest
from unittest.mock import AsyncMock, patch
from app.api.utils import verification_otp_token


@pytest.mark.asyncio
async def test_generate_verification_session_success():
    """
    Test that generate_verification_session successfully creates a token and OTP,
    stores them in Redis, and returns them.
    """
    email = "user@example.com"
    purpose = "reset_password"

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hset = AsyncMock()
        mock_redis.expire = AsyncMock()

        token, otp = await verification_otp_token.generate_verification_session(email, purpose)

        assert isinstance(token, str)
        assert len(token) > 0
        assert otp.isdigit() and len(otp) == 4
        mock_redis.hset.assert_called_once()
        mock_redis.expire.assert_called_once()


@pytest.mark.asyncio
async def test_generate_verification_session_failure():
    """
    Test that generate_verification_session raises an exception when Redis fails to store the session.
    """
    email = "user@example.com"
    purpose = "reset_password"

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hset = AsyncMock(side_effect=Exception("Redis down"))
        mock_redis.expire = AsyncMock()

        with pytest.raises(Exception) as exc_info:
            await verification_otp_token.generate_verification_session(email, purpose)
        assert str(exc_info.value) == "Redis down"


@pytest.mark.asyncio
async def test_verify_otp_and_mark_verified_success():
    """
    Test that verify_otp_and_mark_verified returns True when OTP matches
    and updates the session as verified in Redis.
    """
    purpose = "reset_password"
    token = "verification-token"
    otp = "1234"
    mock_data = {"email": "user@example.com", "otp": otp, "verified": "false"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        mock_redis.hset = AsyncMock()
        mock_redis.expire = AsyncMock()

        result = await verification_otp_token.verify_otp_and_mark_verified(purpose, token, otp)
        assert result is True
        mock_redis.hset.assert_called_once_with(
            f"verification_session:{purpose}:{token}", "verified", "true"
        )
        mock_redis.expire.assert_called_once()


@pytest.mark.asyncio
async def test_verify_otp_and_mark_verified_invalid_otp():
    """
    Test that verify_otp_and_mark_verified returns False when OTP does not match.
    """
    purpose = "reset_password"
    token = "verification-token"
    otp = "9999"
    mock_data = {"email": "user@example.com", "otp": "1234", "verified": "false"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        result = await verification_otp_token.verify_otp_and_mark_verified(purpose, token, otp)
        assert result is False


@pytest.mark.asyncio
async def test_verify_otp_and_mark_verified_no_session():
    """
    Test that verify_otp_and_mark_verified returns False when session does not exist in Redis.
    """
    purpose = "reset_password"
    token = "verification-token"
    otp = "1234"

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value={})
        result = await verification_otp_token.verify_otp_and_mark_verified(purpose, token, otp)
        assert result is False


@pytest.mark.asyncio
async def test_get_verified_session_email_success():
    """
    Test that get_verified_session_email returns the correct email
    when the session exists and is verified.
    """
    purpose = "reset_password"
    token = "verification-token"
    mock_data = {"email": "user@example.com", "verified": "true"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        email = await verification_otp_token.get_verified_session_email(purpose, token)
        assert email == "user@example.com"


@pytest.mark.asyncio
async def test_get_verified_session_email_not_verified():
    """
    Test that get_verified_session_email returns None when the session exists but is not verified.
    """
    purpose = "reset_password"
    token = "verification-token"
    mock_data = {"email": "user@example.com", "verified": "false"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        email = await verification_otp_token.get_verified_session_email(purpose, token)
        assert email is None


@pytest.mark.asyncio
async def test_get_verified_session_email_no_session():
    """
    Test that get_verified_session_email returns None when the session does not exist.
    """
    purpose = "reset_password"
    token = "verification-token"

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.hgetall = AsyncMock(return_value={})
        email = await verification_otp_token.get_verified_session_email(purpose, token)
        assert email is None


@pytest.mark.asyncio
async def test_cleanup_verification_session_success():
    """
    Test that cleanup_verification_session deletes the session from Redis successfully.
    """
    purpose = "reset_password"
    token = "verification-token"

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.delete = AsyncMock()
        await verification_otp_token.cleanup_verification_session(purpose, token)
        mock_redis.delete.assert_called_once_with(f"verification_session:{purpose}:{token}")


@pytest.mark.asyncio
async def test_cleanup_verification_session_failure():
    """
    Test that cleanup_verification_session handles Redis deletion failure gracefully.
    """
    purpose = "reset_password"
    token = "verification-token"

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis:
        mock_redis.delete = AsyncMock(side_effect=Exception("Redis down"))
        await verification_otp_token.cleanup_verification_session(purpose, token)


@pytest.mark.asyncio
async def test_can_resend_allowed():
    """
    Test that can_resend returns True if cooldown period has passed and max resends not reached.
    """
    session_key = "verification_session:test:token"
    mock_data = {"last_sent_at": "0", "resend_count": "0"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis, \
         patch("time.time", return_value=1000):
        mock_redis.hgetall = AsyncMock(return_value=mock_data)

        result = await verification_otp_token.can_resend(session_key)
        assert result is True


@pytest.mark.asyncio
async def test_can_resend_cooldown_not_allowed():
    """
    Test that can_resend returns False if cooldown period has not passed.
    """
    session_key = "verification_session:test:token"
    mock_data = {"last_sent_at": "995", "resend_count": "0"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis, \
         patch("time.time", return_value=1000), \
         patch("app.api.utils.verification_otp_token.settings") as mock_settings:
        mock_settings.RESEND_COOLDOWN_SECONDS = 10
        mock_settings.MAX_RESENDS = 5
        mock_redis.hgetall = AsyncMock(return_value=mock_data)

        result = await verification_otp_token.can_resend(session_key)
        assert result is False


@pytest.mark.asyncio
async def test_can_resend_max_reached():
    """
    Test that can_resend returns False when max resends have been reached.
    """
    session_key = "verification_session:test:token"
    mock_data = {"last_sent_at": "0", "resend_count": "5"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis, \
         patch("time.time", return_value=1000), \
         patch("app.api.utils.verification_otp_token.settings") as mock_settings:
        mock_settings.RESEND_COOLDOWN_SECONDS = 1
        mock_settings.MAX_RESENDS = 5
        mock_redis.hgetall = AsyncMock(return_value=mock_data)

        result = await verification_otp_token.can_resend(session_key)
        assert result is False


@pytest.mark.asyncio
async def test_update_resend_success():
    """
    Test that update_resend updates the resend count and last sent time in Redis.
    """
    session_key = "verification_session:test:token"
    new_otp = "5678"
    mock_data = {"otp": "1234", "last_sent_at": "0", "resend_count": "1"}

    with patch("app.api.utils.verification_otp_token.redis_client") as mock_redis, \
         patch("time.time", return_value=2000), \
         patch("app.api.utils.verification_otp_token.settings") as mock_settings:
        mock_settings.VERIFICATION_SESSION_EXPIRY = 300
        mock_redis.hgetall = AsyncMock(return_value=mock_data)
        mock_redis.hset = AsyncMock()
        mock_redis.expire = AsyncMock()

        await verification_otp_token.update_resend(session_key, new_otp)

        mock_redis.hset.assert_called_once()
        mock_redis.expire.assert_called_once_with(session_key, 300)

