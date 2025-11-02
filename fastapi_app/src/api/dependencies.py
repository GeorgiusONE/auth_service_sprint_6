"""
Common API dependencies.

Provides dependency injection functions for FastAPI endpoints.
"""

from typing import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from db.postgres import get_session
from db.redis_db import get_redis


# Database dependencies

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session dependency.
    
    Yields:
        AsyncSession: Database session
    """
    async for session in get_session():
        yield session


async def get_redis_client() -> Redis:
    """
    Get Redis client dependency.
    
    Returns:
        Redis: Redis client instance
    """
    return await get_redis()