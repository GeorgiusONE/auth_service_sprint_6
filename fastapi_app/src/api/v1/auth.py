"""
Authentication endpoints.

Provides endpoints for user registration, login, token refresh, and logout.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from src.api.dependencies import get_db, get_redis_client, get_current_user
from src.models.entity import User
from src.models.schemas import (
    UserCreate,
    UserResponse,
    LoginRequest,
    TokenResponse,
    RefreshRequest,
    AccessTokenResponse,
)
from src.services.auth import AuthService
from src.core.exceptions import (
    UserAlreadyExistsError,
    InvalidCredentialsError,
    PasswordTooWeakError,
    TokenInvalidError,
    TokenExpiredError,
    TokenRevokedError,
    UserInactiveError,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account in the system",
    responses={
        201: {"description": "User successfully registered"},
        400: {"description": "Invalid input data or password too weak"},
        409: {"description": "User already exists"},
    },
)
async def signup(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> UserResponse:
    """
    Register a new user with the following data:

    - **login**: unique username (min 3 characters)
    - **password**: user password (min 8 characters, will be hashed)
    - **first_name**: user's first name
    - **last_name**: user's last name

    Returns the created user information without password.
    """
    try:
        auth_service = AuthService(db, redis)
        user = await auth_service.register_user(
            login=user_data.login,
            password=user_data.password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
        )

        logger.info(f"New user registered: {user.login}")

        return UserResponse.model_validate(user)

    except UserAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=e.detail,
        )
    except PasswordTooWeakError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error during user registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during registration",
        )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Login to the system",
    description="Authenticate user and return JWT tokens",
    responses={
        200: {"description": "Successfully authenticated"},
        400: {"description": "Invalid credentials"},
        401: {"description": "Authentication failed"},
        403: {"description": "User is not active"},
    },
)
async def login(
    credentials: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> TokenResponse:
    """
    Authenticate user and return access and refresh tokens.

    - **login**: user's login
    - **password**: user's password

    Returns a pair of JWT tokens (access + refresh).

    The login attempt is recorded in the history with device information.
    """
    try:
        # Extract user agent and IP address
        user_agent = request.headers.get("user-agent", "Unknown")
        ip_address = request.headers.get("x-forwarded-for")
        if not ip_address:
            ip_address = request.client.host if request.client else "Unknown"

        auth_service = AuthService(db, redis)

        # Authenticate user
        user = await auth_service.authenticate_user(
            login=credentials.login,
            password=credentials.password,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Create tokens
        tokens = await auth_service.create_tokens(user=user)

        logger.info(f"User logged in: {user.login}")

        return tokens

    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail,
        )
    except UserInactiveError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login",
        )


@router.post(
    "/refresh",
    response_model=AccessTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Get a new access token using refresh token",
    responses={
        200: {"description": "Token successfully refreshed"},
        401: {"description": "Invalid or expired refresh token"},
        403: {"description": "Token has been revoked"},
    },
)
async def refresh(
    refresh_data: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> AccessTokenResponse:
    """
    Refresh the access token using a valid refresh token.

    - **refresh_token**: valid refresh token

    Returns a new access token. The refresh token remains valid.
    """
    try:
        auth_service = AuthService(db, redis)

        # Refresh access token
        access_token = await auth_service.refresh_access_token(refresh_token=refresh_data.refresh_token)

        return AccessTokenResponse(access_token=access_token, token_type="bearer")

    except TokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail,
        )
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail,
        )
    except TokenRevokedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error during token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during token refresh",
        )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout from current session",
    description="Add current access token to blacklist",
    responses={
        204: {"description": "Successfully logged out"},
        401: {"description": "Invalid token"},
    },
)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> None:
    """
    Logout from the current session.

    The access token is added to the blacklist and becomes invalid.
    The refresh token (if provided in the body) is also removed from Redis.

    Requires authentication (Bearer token in Authorization header).
    """
    try:
        # Extract token from Authorization header
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header",
            )

        access_token = auth_header.split(" ")[1]

        auth_service = AuthService(db, redis)

        # Logout (add access token to blacklist)
        await auth_service.logout(
            user_id=current_user.id,
            access_token=access_token,
            refresh_token=None,  # We don't have refresh token here
        )

        logger.info(f"User logged out: {current_user.login}")

    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during logout",
        )


@router.post(
    "/logout-all",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout from all sessions",
    description="Invalidate all tokens by incrementing token version",
    responses={
        204: {"description": "All sessions successfully terminated"},
        401: {"description": "Invalid token"},
    },
)
async def logout_all(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> None:
    """
    Logout from all devices/sessions.

    This increments the user's token version, making all existing tokens invalid.
    All refresh tokens are also removed from Redis.

    The user will need to login again on all devices.

    Requires authentication (Bearer token in Authorization header).
    """
    try:
        auth_service = AuthService(db, redis)

        # Logout from all devices
        await auth_service.logout_all(user_id=current_user.id)

        logger.info(f"User logged out from all devices: {current_user.login}")

    except Exception as e:
        logger.error(f"Error during logout from all devices: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during logout",
        )
