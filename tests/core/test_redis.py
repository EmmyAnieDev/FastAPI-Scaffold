import pytest
from unittest.mock import AsyncMock, patch

from app.api.core.redis import add_jti_to_blocklist, jti_in_blocklist

@pytest.mark.asyncio
@patch("app.api.core.redis.redis_client")
async def test_add_jti_to_blocklist(mock_redis):
    # Arrange
    mock_redis.set = AsyncMock(return_value=True)
    jti = "test-jti-id"

    # Act
    await add_jti_to_blocklist(jti)

    # Assert
    mock_redis.set.assert_called_once_with(name=jti, value="", ex=mock_redis.set.call_args.kwargs.get("ex"))

@pytest.mark.asyncio
@patch("app.api.core.redis.redis_client")
async def test_jti_in_blocklist_found(mock_redis):
    # Arrange
    mock_redis.get = AsyncMock(return_value=b"")
    jti = "existing-jti"

    # Act
    result = await jti_in_blocklist(jti)

    # Assert
    assert result is True
    mock_redis.get.assert_awaited_once_with(jti)

@pytest.mark.asyncio
@patch("app.api.core.redis.redis_client")
async def test_jti_in_blocklist_not_found(mock_redis):
    # Arrange
    mock_redis.get = AsyncMock(return_value=None)
    jti = "non-existent-jti"

    # Act
    result = await jti_in_blocklist(jti)

    # Assert
    assert result is False
    mock_redis.get.assert_awaited_once_with(jti)

@pytest.mark.asyncio
@patch("app.api.core.redis.redis_client")
async def test_jti_in_blocklist_redis_error(mock_redis):
    # Arrange
    mock_redis.get = AsyncMock(side_effect=Exception("Redis error"))
    jti = "error-jti"

    # Act
    result = await jti_in_blocklist(jti)

    # Assert
    assert result is False
