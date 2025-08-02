from app.api.core.redis import redis_client
from app.api.exceptions.exceptions import RateLimiterException
from config import settings

class RateLimiterService:
    def __init__(self, prefix: str, limit: int = settings.DEFAULT_LIMIT, window: int = settings.DEFAULT_WINDOW):
        """
        Initialize a rate limiter.

        Args:
            prefix (str): A unique key to identify the route (e.g., 'login').
            limit (int): Maximum allowed requests.
            window (int): Time window in seconds.
        """
        self.prefix = prefix
        self.limit = limit
        self.window = window

    async def check_limit(self, identifier: str):
        """
        Check if the identifier (usually IP) has exceeded the rate limit.

        Args:
            identifier (str): Client identifier (e.g., IP).

        Raises:
            HTTPException: If rate limit exceeded.
        """
        key = f"rate_limit:{self.prefix}:{identifier}"
        current_count = await redis_client.get(key)

        if current_count is None:
            # First request: set count to 1 and expire in `window` seconds
            await redis_client.set(key, 1, ex=self.window)
        else:
            count = int(current_count)
            if count >= self.limit:
                raise RateLimiterException()
            await redis_client.incr(key)
