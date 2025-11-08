"""
User endpoints.

Provides endpoints for user profile management and login history.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from src.api.dependencies import get_db, get_redis_client, get_current_user
from src.models.entity import User
from src.models.schemas import (
    UserDetailResponse,
    LoginHistoryResponse,
    ChangePasswordRequest,
    MessageResponse,
)
from src.services.user import UserService
from src.services.auth import AuthService
from src.core.exceptions import (
    InvalidPasswordError,
    PasswordTooWeakError,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user information",
    description="Returns detailed information about the authenticated user",
    responses={
        200: {"description": "User information retrieved successfully"},
        401: {"description": "Unauthorized - invalid or missing token"},
    },
)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> UserDetailResponse:
    """
    Get detailed information about the current authenticated user.

    Returns:
    - User ID, login, name
    - List of assigned roles
    - Superuser status
    - Account creation date

    Requires authentication (Bearer token in Authorization header).
    """
    try:
        user_service = UserService(db, redis)

        # Get user with roles
        user_with_roles = await user_service.get_user_with_roles(user_id=current_user.id)

        return user_with_roles

    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while retrieving user information",
        )


@router.get(
    "/me/login-history",
    response_model=LoginHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get login history",
    description="Returns paginated list of login attempts for the current user",
    responses={
        200: {"description": "Login history retrieved successfully"},
        401: {"description": "Unauthorized - invalid or missing token"},
    },
)
async def get_login_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
    page: int = Query(1, ge=1, description="Page number (starting from 1)"),
    size: int = Query(20, ge=1, le=100, description="Number of items per page"),
) -> LoginHistoryResponse:
    """
    Get paginated login history for the current user.

    Query parameters:
    - **page**: Page number (default: 1, minimum: 1)
    - **size**: Items per page (default: 20, minimum: 1, maximum: 100)

    Returns:
    - List of login attempts with device information
    - User agent string
    - IP address
    - Device fingerprint
    - Timestamp
    - Success status
    - Pagination metadata (total, pages)

    Requires authentication (Bearer token in Authorization header).
    """
    try:
        user_service = UserService(db, redis)

        # Get login history with pagination
        history = await user_service.get_login_history(
            user_id=current_user.id,
            page=page,
            size=size,
        )

        return history

    except Exception as e:
        logger.error(f"Error getting login history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while retrieving login history",
        )


@router.put(
    "/me/password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Change password",
    description="Change the password for the current user",
    responses={
        200: {"description": "Password changed successfully"},
        400: {"description": "Invalid old password or weak new password"},
        401: {"description": "Unauthorized - invalid or missing token"},
    },
)
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> MessageResponse:
    """
    Change the password for the current user.

    Request body:
    - **old_password**: Current password for verification
    - **new_password**: New password (min 8 characters, must meet strength requirements)

    Password requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    For security, this operation will logout the user from all other devices.

    Requires authentication (Bearer token in Authorization header).
    """
    try:
        user_service = UserService(db, redis)
        AuthService(db, redis)

        # Change password (this also performs logout_all for security)
        await user_service.change_password(
            user_id=current_user.id,
            old_password=password_data.old_password,
            new_password=password_data.new_password,
            logout_all=True,
        )

        logger.info(f"Password changed for user: {current_user.login}")

        return MessageResponse(message="Password updated successfully")

    except InvalidPasswordError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.detail,
        )
    except PasswordTooWeakError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while changing password",
        )
