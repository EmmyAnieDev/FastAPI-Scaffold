import logging
import redis.asyncio as redis

from config import settings

logger = logging.getLogger(__name__)

# Redis client for storing blocked JTI
jti_blocklist = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=0  # Default Redis DB
)

async def add_jti_to_blocklist(jti: str) -> None:
    """
    Add a JWT ID (jti) to the Redis blocklist with an expiration time.

    Args:
        jti (str): The JWT ID to block.

    Returns:
        None
    """
    try:
        await jti_blocklist.set(name=jti, value="", ex=settings.JTI_EXPIRY)
        logger.info("Added jti to blocklist: %s", jti)
    except Exception as e:
        logger.error("Failed to add jti to Redis blocklist: %s", str(e))


async def jti_in_blocklist(jti: str) -> bool:
    """
    Check if a JWT ID (jti) exists in the Redis blocklist.

    Args:
        jti (str): The JWT ID to check.

    Returns:
        bool: True if the jti is in the blocklist, False otherwise.
    """
    try:
        result = await jti_blocklist.get(jti)
        is_blocked = result is not None
        logger.debug("Checked jti in blocklist: %s -> %s", jti, is_blocked)
        return is_blocked
    except Exception as e:
        logger.error("Failed to check jti in Redis blocklist: %s", str(e))
        return False