"""User service."""
import json
import logging
from typing import Optional
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.exceptions import (
    InvalidPasswordError,
    PasswordTooWeakError,
    UserNotFoundError,
)
from src.core.security import PasswordHasher, validate_password_strength
from src.db.redis_db import (
    cache_user_data,
    cache_user_roles,
    get_cached_user_data,
    get_cached_user_roles,
    invalidate_user_data_cache,
    invalidate_user_roles_cache,
)
from src.models.entity import LoginHistory, Role, User, UserRole
from src.models.schemas import (
    LoginHistoryItem,
    LoginHistoryResponse,
    RoleResponse,
    UserDetailResponse,
    UserWithRoles,
)

logger = logging.getLogger(__name__)


class UserService:
    """Service for user operations."""

    def __init__(self, db: AsyncSession, redis: Redis):
        """Initialize user service.
        
        Args:
            db: Database session
            redis: Redis client
        """
        self.db = db
        self.redis = redis
        self.password_hasher = PasswordHasher()

    async def get_user_by_id(
        self,
        user_id: UUID,
        use_cache: bool = True,
    ) -> User:
        """Get user by ID.
        
        Args:
            user_id: User ID
            use_cache: Whether to use cache
            
        Returns:
            User object
            
        Raises:
            UserNotFoundError: If user not found
        """
        user_id_str = str(user_id)
        
        # Try to get from cache first
        if use_cache:
            cached_data = await get_cached_user_data(self.redis, user_id_str)
            if cached_data:
                logger.debug(f"User data loaded from cache: {user_id}")
                # Note: This returns dict, not User object
                # For full User object with relationships, we need DB query
        
        # Get from database with roles
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            logger.warning(f"User not found: {user_id}")
            raise UserNotFoundError()
        
        # Cache user data
        if use_cache:
            user_data = {
                "id": str(user.id),
                "login": user.login,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
            }
            await cache_user_data(self.redis, user_id_str, user_data)
        
        return user

    async def get_user_by_login(
        self,
        login: str,
    ) -> Optional[User]:
        """Get user by login.
        
        Args:
            login: User login
            
        Returns:
            User object or None if not found
        """
        stmt = select(User).where(User.login == login)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        return user

    async def get_user_with_roles(
        self,
        user_id: UUID,
        use_cache: bool = True,
    ) -> UserWithRoles:
        """Get user with roles information.
        
        Args:
            user_id: User ID
            use_cache: Whether to use cache
            
        Returns:
            User with roles
            
        Raises:
            UserNotFoundError: If user not found
        """
        user_id_str = str(user_id)
        
        # Try to get roles from cache
        cached_roles = None
        if use_cache:
            cached_roles = await get_cached_user_roles(self.redis, user_id_str)
        
        # Get user from database
        user = await self.get_user_by_id(user_id, use_cache=use_cache)
        
        # Use cached roles or get from user object
        if cached_roles:
            logger.debug(f"User roles loaded from cache: {user_id}")
            roles = [RoleResponse(**role) for role in cached_roles]
        else:
            roles = [
                RoleResponse(
                    id=ur.role.id,
                    name=ur.role.name,
                    description=ur.role.description,
                    created_at=ur.role.created_at,
                )
                for ur in user.user_roles
            ]
            
            # Cache roles
            if use_cache:
                roles_data = [
                    {
                        "id": str(role.id),
                        "name": role.name,
                        "description": role.description,
                        "created_at": role.created_at.isoformat(),
                    }
                    for role in roles
                ]
                await cache_user_roles(self.redis, user_id_str, roles_data)
        
        return UserWithRoles(
            id=user.id,
            login=user.login,
            first_name=user.first_name,
            last_name=user.last_name,
            is_superuser=user.is_superuser,
            roles=roles,
            created_at=user.created_at,
        )

    async def update_user(
        self,
        user_id: UUID,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> User:
        """Update user information.
        
        Args:
            user_id: User ID
            first_name: New first name (optional)
            last_name: New last name (optional)
            
        Returns:
            Updated user
            
        Raises:
            UserNotFoundError: If user not found
        """
        # Get user
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            logger.warning(f"User not found for update: {user_id}")
            raise UserNotFoundError()
        
        # Update fields
        if first_name is not None:
            user.first_name = first_name
        if last_name is not None:
            user.last_name = last_name
        
        await self.db.commit()
        await self.db.refresh(user)
        
        # Invalidate cache
        await invalidate_user_data_cache(self.redis, str(user_id))
        
        logger.info(f"User updated: {user.login} (ID: {user_id})")
        
        return user

    async def get_login_history(
        self,
        user_id: UUID,
        page: int = 1,
        size: int = 20,
    ) -> LoginHistoryResponse:
        """Get user login history with pagination.
        
        Args:
            user_id: User ID
            page: Page number (starts from 1)
            size: Items per page
            
        Returns:
            Paginated login history
        """
        # Calculate offset
        offset = (page - 1) * size
        
        # Get total count
        count_stmt = select(func.count()).select_from(LoginHistory).where(
            LoginHistory.user_id == user_id
        )
        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar_one()
        
        # Get paginated items
        stmt = (
            select(LoginHistory)
            .where(LoginHistory.user_id == user_id)
            .order_by(LoginHistory.login_at.desc())
            .limit(size)
            .offset(offset)
        )
        result = await self.db.execute(stmt)
        history_items = result.scalars().all()
        
        # Convert to response schema
        items = [
            LoginHistoryItem(
                id=item.id,
                user_agent=item.user_agent,
                ip_address=item.ip_address,
                fingerprint=item.fingerprint,
                login_at=item.login_at,
                success=item.success,
            )
            for item in history_items
        ]
        
        # Calculate total pages
        pages = (total + size - 1) // size if total > 0 else 1
        
        return LoginHistoryResponse(
            items=items,
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def change_password(
        self,
        user_id: UUID,
        old_password: str,
        new_password: str,
        logout_all_devices: bool = False,
    ) -> None:
        """Change user password.
        
        Args:
            user_id: User ID
            old_password: Current password
            new_password: New password
            logout_all_devices: Whether to logout from all devices after change
            
        Raises:
            UserNotFoundError: If user not found
            InvalidPasswordError: If old password is incorrect
            PasswordTooWeakError: If new password is too weak
        """
        # Get user
        stmt = select(User).where(User.id == user_id)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()
        
        if not user:
            logger.warning(f"User not found for password change: {user_id}")
            raise UserNotFoundError()
        
        # Verify old password
        if not self.password_hasher.verify_password(old_password, user.password):
            logger.warning(f"Invalid old password for user: {user_id}")
            raise InvalidPasswordError()
        
        # Validate new password strength
        if not validate_password_strength(new_password):
            logger.warning(f"Weak new password attempt for user: {user_id}")
            raise PasswordTooWeakError()
        
        # Hash and update password
        new_password_hash = self.password_hasher.hash_password(new_password)
        user.password = new_password_hash
        
        await self.db.commit()
        
        logger.info(f"Password changed for user: {user.login} (ID: {user_id})")
        
        # Optional: logout from all devices for security
        if logout_all_devices:
            from src.services.auth import AuthService
            auth_service = AuthService(self.db, self.redis)
            await auth_service.logout_all(user_id)
            logger.info(f"User logged out from all devices after password change: {user_id}")

    async def record_login_attempt(
        self,
        user_id: UUID,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        fingerprint: Optional[str] = None,
        success: bool = True,
    ) -> None:
        """Record a login attempt.
        
        Args:
            user_id: User ID
            user_agent: Browser/client user agent
            ip_address: Client IP address
            fingerprint: Device fingerprint
            success: Whether login was successful
        """
        login_record = LoginHistory(
            user_id=user_id,
            user_agent=user_agent,
            ip_address=ip_address,
            fingerprint=fingerprint,
            success=success,
        )
        
        self.db.add(login_record)
        await self.db.commit()
        
        logger.debug(
            f"Login attempt recorded for user {user_id}: "
            f"success={success}, ip={ip_address}"
        )
