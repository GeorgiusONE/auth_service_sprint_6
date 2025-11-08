"""
Common API dependencies.

Provides dependency injection functions for FastAPI endpoints.
"""

from typing import AsyncGenerator, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from src.db.postgres import get_session
from src.db.redis_db import get_redis
from src.models.entity import User
from src.models.schemas import TokenPayload
from src.services.auth import AuthService
from src.services.user import UserService
from src.core.exceptions import (
    TokenInvalidError,
    TokenExpiredError,
    TokenBlacklistedError,
    UserNotFoundError,
    UserInactiveError,
)


# Security scheme
security = HTTPBearer()


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


# Authentication dependencies


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> User:
    """
    Get current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer token credentials
        db: Database session
        redis: Redis client

    Returns:
        User: Current authenticated user

    Raises:
        HTTPException: If token is invalid, expired, or user not found
    """
    token = credentials.credentials

    try:
        # Initialize auth service
        auth_service = AuthService(db, redis)

        # Verify token and get payload
        payload: TokenPayload = await auth_service.verify_token(token=token, token_type="access")

        # Get user from database
        user_service = UserService(db, redis)
        user = await user_service.get_user_by_id(payload.sub)

        # Check if user is active
        if not user.is_active:
            raise UserInactiveError()

        return user

    except TokenInvalidError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenBlacklistedError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except UserInactiveError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_role(role_name: str) -> Callable:
    """
    Create a dependency that requires a specific role.

    Args:
        role_name: Name of the required role

    Returns:
        Callable: Dependency function that checks for the role
    """

    async def check_role(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
        redis: Redis = Depends(get_redis_client),
    ) -> User:
        """
        Check if user has the required role.

        Args:
            current_user: Current authenticated user
            db: Database session
            redis: Redis client

        Returns:
            User: Current user if they have the role

        Raises:
            HTTPException: If user doesn't have the required role
        """
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user

        # Check if user has the required role
        from src.services.role import RoleService

        role_service = RoleService(db, redis)

        result = await role_service.check_user_permission(user_id=current_user.id, role_name=role_name)

        if not result.has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role_name}' is required for this operation",
            )

        return current_user

    return check_role


async def require_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Require that the current user is a superuser.

    Args:
        current_user: Current authenticated user

    Returns:
        User: Current user if they are a superuser

    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )

    return current_user


def require_admin_or_superuser(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> User:
    """
    Require that the current user is either admin or superuser.

    Args:
        current_user: Current authenticated user
        db: Database session
        redis: Redis client

    Returns:
        User: Current user if they have admin privileges

    Raises:
        HTTPException: If user is neither admin nor superuser
    """
    # Superusers always have access
    if current_user.is_superuser:
        return current_user

    # Check if user has admin role
    from src.services.role import RoleService

    role_service = RoleService(db, redis)

    # This will be executed synchronously in the dependency
    import asyncio

    result = asyncio.run(role_service.check_user_permission(user_id=current_user.id, role_name="admin"))

    if not result.has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or superuser access required",
        )

    return current_user
