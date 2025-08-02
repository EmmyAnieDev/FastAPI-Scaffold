import pytest
from unittest.mock import AsyncMock, patch

from app.api.exceptions.exceptions import RateLimiterException
from app.api.v1.services.rate_limiter import RateLimiterService


@pytest.mark.asyncio
class TestRateLimiterService:

    @patch("app.api.v1.services.rate_limiter.redis_client", new_callable=AsyncMock)
    async def test_first_request_sets_key(self, mock_redis):
        """
        Should set Redis key and not increment on first request.
        """
        mock_redis.get.return_value = None

        limiter = RateLimiterService(prefix="test", limit=3, window=60)
        await limiter.check_limit("127.0.0.1")

        mock_redis.set.assert_called_once_with("rate_limit:test:127.0.0.1", 1, ex=60)
        mock_redis.incr.assert_not_called()


    @patch("app.api.v1.services.rate_limiter.redis_client", new_callable=AsyncMock)
    async def test_within_limit_increments_key(self, mock_redis):
        """
        Should increment Redis key when request is within limit.
        """
        mock_redis.get.return_value = "2"

        limiter = RateLimiterService(prefix="test", limit=5, window=60)
        await limiter.check_limit("192.168.0.1")

        mock_redis.incr.assert_called_once_with("rate_limit:test:192.168.0.1")
        

    @patch("app.api.v1.services.rate_limiter.redis_client", new_callable=AsyncMock)
    async def test_exceed_limit_raises_exception(self, mock_redis):
        """
        Should raise RateLimiterException when limit is exceeded.
        """
        mock_redis.get.return_value = "5"

        limiter = RateLimiterService(prefix="test", limit=5, window=60)

        with pytest.raises(RateLimiterException):
            await limiter.check_limit("10.0.0.1")

        mock_redis.incr.assert_not_called()
