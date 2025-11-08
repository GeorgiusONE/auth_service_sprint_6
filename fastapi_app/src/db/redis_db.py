"""
Redis database connection module.

Provides async Redis client and token/cache management utilities.
"""

from typing import Optional
import json

from redis.asyncio import Redis, ConnectionPool

from src.core.config import settings


# Create connection pool
redis_pool: Optional[ConnectionPool] = None

# Global Redis client instance
redis_client: Optional[Redis] = None


async def get_redis_pool() -> ConnectionPool:
    """
    Get or create Redis connection pool.

    Returns:
        ConnectionPool: Redis connection pool
    """
    global redis_pool

    if redis_pool is None:
        redis_pool = ConnectionPool.from_url(
            settings.redis_url,
            decode_responses=True,  # Automatically decode responses to strings
            max_connections=50,
            retry_on_timeout=True,
        )

    return redis_pool


async def get_redis() -> Redis:
    """
    Dependency function that provides Redis client.

    Returns:
        Redis: Redis client instance
    """
    pool = await get_redis_pool()
    return Redis(connection_pool=pool)


async def init_redis() -> None:
    """
    Initialize Redis connection.

    Should be called on application startup.
    """
    global redis_client

    pool = await get_redis_pool()
    redis_client = Redis(connection_pool=pool)

    # Test connection
    await redis_client.ping()


async def close_redis() -> None:
    """
    Close Redis connections.

    Should be called on application shutdown.
    """
    global redis_client, redis_pool

    if redis_client:
        await redis_client.close()
        redis_client = None

    if redis_pool:
        await redis_pool.disconnect()
        redis_pool = None


# Token management utilities


async def save_refresh_token(redis: Redis, user_id: str, jti: str, refresh_token: str, expire_seconds: int) -> None:
    """
    Save refresh token to Redis.

    Args:
        redis: Redis client
        user_id: User ID
        jti: JWT ID
        refresh_token: Refresh token value
        expire_seconds: Token expiration time in seconds
    """
    key = f"refresh:{user_id}:{jti}"
    await redis.setex(key, expire_seconds, refresh_token)


async def get_refresh_token(redis: Redis, user_id: str, jti: str) -> Optional[str]:
    """
    Get refresh token from Redis.

    Args:
        redis: Redis client
        user_id: User ID
        jti: JWT ID

    Returns:
        Optional[str]: Refresh token if exists, None otherwise
    """
    key = f"refresh:{user_id}:{jti}"
    return await redis.get(key)


async def delete_refresh_token(redis: Redis, user_id: str, jti: str) -> None:
    """
    Delete refresh token from Redis.

    Args:
        redis: Redis client
        user_id: User ID
        jti: JWT ID
    """
    key = f"refresh:{user_id}:{jti}"
    await redis.delete(key)


async def delete_all_refresh_tokens(redis: Redis, user_id: str) -> None:
    """
    Delete all refresh tokens for a user.

    Args:
        redis: Redis client
        user_id: User ID
    """
    pattern = f"refresh:{user_id}:*"
    cursor = 0

    while True:
        cursor, keys = await redis.scan(cursor, match=pattern, count=100)
        if keys:
            await redis.delete(*keys)
        if cursor == 0:
            break


async def add_token_to_blacklist(redis: Redis, jti: str, user_id: str, expire_seconds: int) -> None:
    """
    Add access token to blacklist.

    Args:
        redis: Redis client
        jti: JWT ID
        user_id: User ID
        expire_seconds: Remaining token lifetime in seconds
    """
    key = f"blacklist:{jti}"
    await redis.setex(key, expire_seconds, user_id)


async def is_token_blacklisted(redis: Redis, jti: str) -> bool:
    """
    Check if token is blacklisted.

    Args:
        redis: Redis client
        jti: JWT ID

    Returns:
        bool: True if token is blacklisted, False otherwise
    """
    key = f"blacklist:{jti}"
    return await redis.exists(key) > 0


async def get_token_version(redis: Redis, user_id: str) -> int:
    """
    Get current token version for user.

    Args:
        redis: Redis client
        user_id: User ID

    Returns:
        int: Current token version (default: 1)
    """
    key = f"token_version:{user_id}"
    version = await redis.get(key)
    return int(version) if version else 1


async def increment_token_version(redis: Redis, user_id: str) -> int:
    """
    Increment token version (for logout from all devices).

    Args:
        redis: Redis client
        user_id: User ID

    Returns:
        int: New token version
    """
    key = f"token_version:{user_id}"
    # If key doesn't exist, it will be created with value 1
    return await redis.incr(key)


# Cache management utilities


async def cache_user_roles(
    redis: Redis, user_id: str, roles: list[dict], expire_seconds: int = 300  # 5 minutes
) -> None:
    """
    Cache user roles.

    Args:
        redis: Redis client
        user_id: User ID
        roles: List of role dictionaries
        expire_seconds: Cache expiration time (default: 5 minutes)
    """
    key = f"user_roles:{user_id}"
    await redis.setex(key, expire_seconds, json.dumps(roles))


async def get_cached_user_roles(redis: Redis, user_id: str) -> Optional[list[dict]]:
    """
    Get cached user roles.

    Args:
        redis: Redis client
        user_id: User ID

    Returns:
        Optional[list[dict]]: List of roles if cached, None otherwise
    """
    key = f"user_roles:{user_id}"
    data = await redis.get(key)
    return json.loads(data) if data else None


async def invalidate_user_roles_cache(redis: Redis, user_id: str) -> None:
    """
    Invalidate user roles cache.

    Args:
        redis: Redis client
        user_id: User ID
    """
    key = f"user_roles:{user_id}"
    await redis.delete(key)


async def cache_user_data(redis: Redis, user_id: str, user_data: dict, expire_seconds: int = 300) -> None:  # 5 minutes
    """
    Cache user data.

    Args:
        redis: Redis client
        user_id: User ID
        user_data: User data dictionary
        expire_seconds: Cache expiration time (default: 5 minutes)
    """
    key = f"user:{user_id}"
    await redis.setex(key, expire_seconds, json.dumps(user_data))


async def get_cached_user_data(redis: Redis, user_id: str) -> Optional[dict]:
    """
    Get cached user data.

    Args:
        redis: Redis client
        user_id: User ID

    Returns:
        Optional[dict]: User data if cached, None otherwise
    """
    key = f"user:{user_id}"
    data = await redis.get(key)
    return json.loads(data) if data else None


async def invalidate_user_data_cache(redis: Redis, user_id: str) -> None:
    """
    Invalidate user data cache.

    Args:
        redis: Redis client
        user_id: User ID
    """
    key = f"user:{user_id}"
    await redis.delete(key)
