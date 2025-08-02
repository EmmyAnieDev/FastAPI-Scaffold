import logging
from fastapi import Request
from app.api.v1.services.rate_limiter import RateLimiterService
from config import settings

logger = logging.getLogger(__name__)

def rate_limiter(limit: int = settings.DEFAULT_LIMIT, window: int = settings.DEFAULT_WINDOW, prefix: str = settings.DEFAULT_PREFIX):
    """
    Dependency function for applying rate limiting to a FastAPI route.

    This function returns a FastAPI dependency that limits the number of requests 
    from a single IP address within a specified time window.

    Args:
        limit (int): Maximum number of allowed requests within the time window.
        window (int): Time window for rate limiting in seconds.
        prefix (str): Redis key prefix to namespace rate limits for different route groups.

    Returns:
        Depends: A FastAPI dependency that raises an exception if the rate limit is exceeded.
    """
    async def limiter_dependency(request: Request):
        ip = request.client.host
        logger.info(f"Rate limit check for IP: {ip} [prefix={prefix}]")
        limiter = RateLimiterService(prefix=prefix, limit=limit, window=window)
        await limiter.check_limit(ip)

    return limiter_dependency
