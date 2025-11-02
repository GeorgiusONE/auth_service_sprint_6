"""Authentication service."""
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.config import settings
from src.core.exceptions import (
    InvalidCredentialsError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    UserAlreadyExistsError,
    UserInactiveError,
    UserNotFoundError,
    PasswordTooWeakError,
)
from src.core.security import (
    PasswordHasher,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_device_fingerprint,
    get_token_expiry,
    get_token_jti,
    validate_password_strength,
    verify_token,
)
from src.db.redis_db import (
    add_token_to_blacklist,
    delete_all_refresh_tokens,
    delete_refresh_token,
    get_refresh_token,
    get_token_version,
    increment_token_version,
    is_token_blacklisted,
    save_refresh_token,
)
from src.models.entity import LoginHistory, User, UserRole
from src.models.schemas import (
    TokenPayload,
    TokenResponse,
    UserCreate,
    UserResponse,
)

logger = logging.getLogger(__name__)


class AuthService:
    """Service for authentication operations."""

    def __init__(self, db: AsyncSession, redis: Redis):
        """Initialize auth service.
        
        Args:
            db: Database session
            redis: Redis client
        """
        self.db = db
        self.redis = redis
        self.password_hasher = PasswordHasher()

    async def register_user(
        self,
        user_data: UserCreate,
    ) -> UserResponse:
        """Register a new user.
        
        Args:
            user_data: User registration data
            
        Returns:
            Created user information
            
        Raises:
            UserAlreadyExistsError: If user with this login already exists
            PasswordTooWeakError: If password doesn't meet requirements
        """
        # Check if user already exists
        stmt = select(User).where(User.login == user_data.login)
        result = await self.db.execute(stmt)
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            logger.warning(f"Registration attempt with existing login: {user_data.login}")
            raise UserAlreadyExistsError()
        
        # Validate password strength
        if not validate_password_strength(user_data.password):
            logger.warning(f"Weak password attempt for user: {user_data.login}")
            raise PasswordTooWeakError()
        
        # Hash password
        hashed_password = self.password_hasher.hash_password(user_data.password)
        
        # Create user
        new_user = User(
            login=user_data.login,
            password=hashed_password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
        )
        
        self.db.add(new_user)
        await self.db.commit()
        await self.db.refresh(new_user)
        
        logger.info(f"User registered successfully: {new_user.login} (ID: {new_user.id})")
        
        return UserResponse(
            id=new_user.id,
            login=new_user.login,
            first_name=new_user.first_name,
            last_name=new_user.last_name,
            created_at=new_user.created_at,
        )

    async def authenticate_user(
        self,
        login: str,
        password: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> User:
        """Authenticate user with login and password.
        
        Args:
            login: User login
            password: User password
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            Authenticated user
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
            UserInactiveError: If user is not active
        """
        # Find user by login with roles
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).where(User.login == login)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        # Record failed attempt
        if not user or not self.password_hasher.verify_password(password, user.password):
            if user:
                await self._record_login_attempt(
                    user_id=user.id,
                    user_agent=user_agent,
                    ip_address=ip_address,
                    success=False,
                )
            logger.warning(f"Failed login attempt for: {login} from IP: {ip_address}")
            raise InvalidCredentialsError()
        
        # Check if user is active
        if not user.is_active:
            logger.warning(f"Login attempt for inactive user: {login}")
            raise UserInactiveError()
        
        # Record successful login
        await self._record_login_attempt(
            user_id=user.id,
            user_agent=user_agent,
            ip_address=ip_address,
            success=True,
        )
        
        logger.info(
            f"User authenticated successfully: {user.login} (ID: {user.id})",
            extra={"user_id": str(user.id), "ip_address": ip_address}
        )
        
        return user

    async def create_tokens(
        self,
        user: User,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> TokenResponse:
        """Create access and refresh tokens for user.
        
        Args:
            user: User to create tokens for
            user_agent: Browser/client user agent
            ip_address: Client IP address
            
        Returns:
            Token pair (access + refresh)
        """
        # Get or initialize token version
        token_version = await get_token_version(self.redis, str(user.id))
        if token_version is None:
            token_version = 1
            await self.redis.set(f"token_version:{user.id}", token_version)
        
        # Extract role names
        role_names = [ur.role.name for ur in user.user_roles]
        
        # Create access token
        access_token = create_access_token(
            user_id=user.id,
            login=user.login,
            roles=role_names,
            version=token_version,
        )
        
        # Create refresh token
        refresh_token, refresh_jti = create_refresh_token(user_id=user.id)
        
        # Save refresh token to Redis
        refresh_expire_seconds = settings.refresh_token_expire_days * 24 * 3600
        await save_refresh_token(
            redis=self.redis,
            user_id=str(user.id),
            jti=refresh_jti,
            token=refresh_token,
            expire_seconds=refresh_expire_seconds,
        )
        
        logger.info(f"Tokens created for user: {user.login} (ID: {user.id})")
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    async def refresh_access_token(
        self,
        refresh_token: str,
    ) -> str:
        """Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New access token
            
        Raises:
            TokenInvalidError: If refresh token is invalid
            TokenExpiredError: If refresh token is expired
            TokenRevokedError: If refresh token was revoked
        """
        # Decode and verify refresh token
        try:
            payload = decode_token(refresh_token)
        except TokenExpiredError:
            logger.warning("Attempt to use expired refresh token")
            raise
        except Exception as e:
            logger.warning(f"Invalid refresh token: {str(e)}")
            raise TokenInvalidError()
        
        # Verify it's a refresh token
        if not verify_token(payload, "refresh"):
            logger.warning("Attempt to use non-refresh token for refresh")
            raise TokenInvalidError()
        
        user_id = payload.get("sub")
        jti = payload.get("jti")
        
        # Check if token exists in Redis (not revoked)
        stored_token = await get_refresh_token(self.redis, user_id, jti)
        if not stored_token:
            logger.warning(f"Revoked refresh token used for user: {user_id}")
            raise TokenRevokedError()
        
        # Check token version
        current_version = await get_token_version(self.redis, user_id)
        if current_version is None:
            current_version = 1
        
        # Get user with roles
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).where(User.id == UUID(user_id))
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            logger.error(f"User not found for refresh token: {user_id}")
            raise UserNotFoundError()
        
        if not user.is_active:
            logger.warning(f"Inactive user attempted token refresh: {user_id}")
            raise UserInactiveError()
        
        # Extract role names
        role_names = [ur.role.name for ur in user.user_roles]
        
        # Create new access token
        access_token = create_access_token(
            user_id=user.id,
            login=user.login,
            roles=role_names,
            version=current_version,
        )
        
        logger.info(f"Access token refreshed for user: {user.login} (ID: {user.id})")
        
        return access_token

    async def logout(
        self,
        access_token: str,
        refresh_token: Optional[str] = None,
    ) -> None:
        """Logout user from current session.
        
        Args:
            access_token: User's access token
            refresh_token: User's refresh token (optional)
        """
        # Add access token to blacklist
        try:
            jti = get_token_jti(access_token)
            expiry = get_token_expiry(access_token)
            payload = decode_token(access_token)
            user_id = payload.get("sub")
            
            # Calculate remaining TTL
            now = datetime.utcnow()
            ttl = int((expiry - now).total_seconds())
            
            if ttl > 0:
                await add_token_to_blacklist(
                    redis=self.redis,
                    jti=jti,
                    user_id=user_id,
                    ttl=ttl,
                )
        except Exception as e:
            logger.error(f"Error adding token to blacklist: {str(e)}")
        
        # Delete refresh token if provided
        if refresh_token:
            try:
                refresh_payload = decode_token(refresh_token)
                refresh_jti = refresh_payload.get("jti")
                user_id = refresh_payload.get("sub")
                
                await delete_refresh_token(
                    redis=self.redis,
                    user_id=user_id,
                    jti=refresh_jti,
                )
            except Exception as e:
                logger.error(f"Error deleting refresh token: {str(e)}")
        
        logger.info(f"User logged out: {user_id}")

    async def logout_all(
        self,
        user_id: UUID,
    ) -> None:
        """Logout user from all devices.
        
        Args:
            user_id: User ID to logout
        """
        user_id_str = str(user_id)
        
        # Increment token version
        new_version = await increment_token_version(self.redis, user_id_str)
        
        # Delete all refresh tokens
        await delete_all_refresh_tokens(self.redis, user_id_str)
        
        logger.info(
            f"User logged out from all devices: {user_id} (new version: {new_version})"
        )

    async def verify_token(
        self,
        token: str,
        token_type: str = "access",
    ) -> TokenPayload:
        """Verify and validate token.
        
        Args:
            token: JWT token to verify
            token_type: Expected token type (access or refresh)
            
        Returns:
            Token payload
            
        Raises:
            TokenInvalidError: If token is invalid
            TokenExpiredError: If token is expired
            TokenBlacklistedError: If token is blacklisted
        """
        # Decode token
        try:
            payload = decode_token(token)
        except TokenExpiredError:
            raise
        except Exception as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise TokenInvalidError()
        
        # Verify token type
        if not verify_token(payload, token_type):
            logger.warning(f"Token type mismatch: expected {token_type}")
            raise TokenInvalidError()
        
        jti = payload.get("jti")
        user_id = payload.get("sub")
        
        # Check if token is blacklisted (only for access tokens)
        if token_type == "access":
            is_blacklisted = await is_token_blacklisted(self.redis, jti)
            if is_blacklisted:
                logger.warning(f"Blacklisted token used: {jti}")
                raise TokenInvalidError()
            
            # Check token version
            token_version = payload.get("version", 0)
            current_version = await get_token_version(self.redis, user_id)
            
            if current_version is not None and int(current_version) != token_version:
                logger.warning(
                    f"Token version mismatch for user {user_id}: "
                    f"token={token_version}, current={current_version}"
                )
                raise TokenInvalidError()
        
        return TokenPayload(**payload)

    async def _record_login_attempt(
        self,
        user_id: UUID,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
    ) -> None:
        """Record login attempt in history.
        
        Args:
            user_id: User ID
            user_agent: Browser/client user agent
            ip_address: Client IP address
            success: Whether login was successful
        """
        fingerprint = None
        if user_agent and ip_address:
            fingerprint = generate_device_fingerprint(user_agent, ip_address)
        
        login_record = LoginHistory(
            user_id=user_id,
            user_agent=user_agent,
            ip_address=ip_address,
            fingerprint=fingerprint,
            success=success,
        )
        
        self.db.add(login_record)
        await self.db.commit()
