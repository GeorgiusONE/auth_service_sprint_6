"""Role service."""
import logging
from typing import List, Optional
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    RoleAlreadyAssignedError,
    RoleAlreadyExistsError,
    RoleNotFoundError,
    UserNotFoundError,
)
from src.db.redis_db import (
    cache_user_roles,
    get_cached_user_roles,
    invalidate_user_roles_cache,
)
from src.models.entity import Role, User, UserRole
from src.models.schemas import (
    PermissionCheckResponse,
    RoleAssignmentResponse,
    RoleCreate,
    RoleDetailResponse,
    RoleResponse,
    RolesListResponse,
    RoleUpdate,
)

logger = logging.getLogger(__name__)


class RoleService:
    """Service for role operations."""

    def __init__(self, db: AsyncSession, redis: Redis):
        """Initialize role service.

        Args:
            db: Database session
            redis: Redis client
        """
        self.db = db
        self.redis = redis

    async def create_role(
        self,
        role_data: RoleCreate,
    ) -> RoleResponse:
        """Create a new role.

        Args:
            role_data: Role creation data

        Returns:
            Created role information

        Raises:
            RoleAlreadyExistsError: If role with this name already exists
        """
        # Check if role already exists
        stmt = select(Role).where(Role.name == role_data.name)
        result = await self.db.execute(stmt)
        existing_role = result.scalar_one_or_none()

        if existing_role:
            logger.warning(f"Role creation attempt with existing name: {role_data.name}")
            raise RoleAlreadyExistsError()

        # Create role
        new_role = Role(
            name=role_data.name,
            description=role_data.description,
        )

        self.db.add(new_role)

        try:
            await self.db.commit()
            await self.db.refresh(new_role)
        except IntegrityError:
            await self.db.rollback()
            logger.error(f"IntegrityError creating role: {role_data.name}")
            raise RoleAlreadyExistsError()

        logger.info(f"Role created: {new_role.name} (ID: {new_role.id})")

        return RoleResponse(
            id=new_role.id,
            name=new_role.name,
            description=new_role.description,
            created_at=new_role.created_at,
        )

    async def get_roles(self) -> RolesListResponse:
        """Get all roles.

        Returns:
            List of all roles
        """
        stmt = select(Role).order_by(Role.name)
        result = await self.db.execute(stmt)
        roles = result.scalars().all()

        items = [
            RoleResponse(
                id=role.id,
                name=role.name,
                description=role.description,
                created_at=role.created_at,
            )
            for role in roles
        ]

        return RolesListResponse(
            items=items,
            total=len(items),
        )

    async def get_role_by_id(
        self,
        role_id: UUID,
    ) -> RoleDetailResponse:
        """Get role by ID.

        Args:
            role_id: Role ID

        Returns:
            Role information

        Raises:
            RoleNotFoundError: If role not found
        """
        stmt = select(Role).where(Role.id == role_id)
        result = await self.db.execute(stmt)
        role = result.scalar_one_or_none()

        if not role:
            logger.warning(f"Role not found: {role_id}")
            raise RoleNotFoundError()

        return RoleDetailResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_at=role.created_at,
            updated_at=role.updated_at,
        )

    async def get_role_by_name(
        self,
        name: str,
    ) -> Optional[Role]:
        """Get role by name.

        Args:
            name: Role name

        Returns:
            Role object or None if not found
        """
        stmt = select(Role).where(Role.name == name)
        result = await self.db.execute(stmt)
        role = result.scalar_one_or_none()

        return role

    async def update_role(
        self,
        role_id: UUID,
        role_data: RoleUpdate,
    ) -> RoleDetailResponse:
        """Update role information.

        Args:
            role_id: Role ID
            role_data: Role update data

        Returns:
            Updated role information

        Raises:
            RoleNotFoundError: If role not found
            RoleAlreadyExistsError: If new name already exists
        """
        # Get role
        stmt = select(Role).where(Role.id == role_id)
        result = await self.db.execute(stmt)
        role = result.scalar_one_or_none()

        if not role:
            logger.warning(f"Role not found for update: {role_id}")
            raise RoleNotFoundError()

        # Check if new name already exists (if name is being changed)
        if role_data.name and role_data.name != role.name:
            existing_stmt = select(Role).where(Role.name == role_data.name)
            existing_result = await self.db.execute(existing_stmt)
            existing_role = existing_result.scalar_one_or_none()

            if existing_role:
                logger.warning(f"Role update attempt with existing name: {role_data.name}")
                raise RoleAlreadyExistsError()

            role.name = role_data.name

        # Update description
        if role_data.description is not None:
            role.description = role_data.description

        try:
            await self.db.commit()
            await self.db.refresh(role)
        except IntegrityError:
            await self.db.rollback()
            logger.error(f"IntegrityError updating role: {role_id}")
            raise RoleAlreadyExistsError()

        logger.info(f"Role updated: {role.name} (ID: {role_id})")

        return RoleDetailResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_at=role.created_at,
            updated_at=role.updated_at,
        )

    async def delete_role(
        self,
        role_id: UUID,
    ) -> None:
        """Delete a role.

        Args:
            role_id: Role ID

        Raises:
            RoleNotFoundError: If role not found
        """
        # Get role
        stmt = select(Role).where(Role.id == role_id)
        result = await self.db.execute(stmt)
        role = result.scalar_one_or_none()

        if not role:
            logger.warning(f"Role not found for deletion: {role_id}")
            raise RoleNotFoundError()

        # Get all users with this role for cache invalidation
        user_roles_stmt = select(UserRole).where(UserRole.role_id == role_id)
        user_roles_result = await self.db.execute(user_roles_stmt)
        user_roles = user_roles_result.scalars().all()

        user_ids = [str(ur.user_id) for ur in user_roles]

        # Delete role (CASCADE will delete user_roles)
        await self.db.delete(role)
        await self.db.commit()

        # Invalidate cache for all affected users
        for user_id in user_ids:
            await invalidate_user_roles_cache(self.redis, user_id)

        logger.info(f"Role deleted: {role.name} (ID: {role_id}), " f"affected {len(user_ids)} users")

    async def assign_role_to_user(
        self,
        role_id: UUID,
        user_id: UUID,
    ) -> RoleAssignmentResponse:
        """Assign role to user.

        Args:
            role_id: Role ID
            user_id: User ID

        Returns:
            Assignment confirmation

        Raises:
            RoleNotFoundError: If role not found
            UserNotFoundError: If user not found
            RoleAlreadyAssignedError: If user already has this role
        """
        # Check if role exists
        role_stmt = select(Role).where(Role.id == role_id)
        role_result = await self.db.execute(role_stmt)
        role = role_result.scalar_one_or_none()

        if not role:
            logger.warning(f"Role not found for assignment: {role_id}")
            raise RoleNotFoundError()

        # Check if user exists
        user_stmt = select(User).where(User.id == user_id)
        user_result = await self.db.execute(user_stmt)
        user = user_result.scalar_one_or_none()

        if not user:
            logger.warning(f"User not found for role assignment: {user_id}")
            raise UserNotFoundError()

        # Check if assignment already exists
        existing_stmt = select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )
        existing_result = await self.db.execute(existing_stmt)
        existing_assignment = existing_result.scalar_one_or_none()

        if existing_assignment:
            logger.warning(f"Role already assigned: role={role_id}, user={user_id}")
            raise RoleAlreadyAssignedError()

        # Create assignment
        user_role = UserRole(
            user_id=user_id,
            role_id=role_id,
        )

        self.db.add(user_role)

        try:
            await self.db.commit()
        except IntegrityError:
            await self.db.rollback()
            logger.error(f"IntegrityError assigning role: role={role_id}, user={user_id}")
            raise RoleAlreadyAssignedError()

        # Invalidate user roles cache
        await invalidate_user_roles_cache(self.redis, str(user_id))

        logger.info(f"Role assigned: {role.name} to user {user.login} " f"(role_id={role_id}, user_id={user_id})")

        return RoleAssignmentResponse(
            message="Role assigned successfully",
            user_id=user_id,
            role_id=role_id,
        )

    async def remove_role_from_user(
        self,
        role_id: UUID,
        user_id: UUID,
    ) -> None:
        """Remove role from user.

        Args:
            role_id: Role ID
            user_id: User ID

        Raises:
            RoleNotFoundError: If role or assignment not found
        """
        # Find assignment
        stmt = select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )
        result = await self.db.execute(stmt)
        user_role = result.scalar_one_or_none()

        if not user_role:
            logger.warning(f"Role assignment not found for removal: " f"role={role_id}, user={user_id}")
            raise RoleNotFoundError()

        # Delete assignment
        await self.db.delete(user_role)
        await self.db.commit()

        # Invalidate user roles cache
        await invalidate_user_roles_cache(self.redis, str(user_id))

        logger.info(f"Role removed from user: role_id={role_id}, user_id={user_id}")

    async def check_user_permission(
        self,
        user_id: UUID,
        required_role: str,
    ) -> PermissionCheckResponse:
        """Check if user has required role.

        Args:
            user_id: User ID
            required_role: Required role name

        Returns:
            Permission check result
        """
        user_roles = await self.get_user_roles(user_id)
        role_names = [role.name for role in user_roles]

        has_permission = required_role in role_names

        logger.debug(f"Permission check for user {user_id}: " f"required={required_role}, has={has_permission}")

        return PermissionCheckResponse(
            has_permission=has_permission,
            user_id=user_id,
            role=required_role,
        )

    async def get_user_roles(
        self,
        user_id: UUID,
        use_cache: bool = True,
    ) -> List[Role]:
        """Get all roles for a user.

        Args:
            user_id: User ID
            use_cache: Whether to use cache

        Returns:
            List of user's roles
        """
        user_id_str = str(user_id)

        # Try to get from cache
        if use_cache:
            cached_roles = await get_cached_user_roles(self.redis, user_id_str)
            if cached_roles:
                logger.debug(f"User roles loaded from cache: {user_id}")
                # Convert cached data back to Role objects
                roles = []
                for role_data in cached_roles:
                    # We need to create Role objects, but we only have basic data
                    # For now, return the cached data as is and let caller handle it
                    # In practice, we might want to return RoleResponse objects instead
                    pass

        # Get from database
        stmt = (
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
            .order_by(Role.name)
        )
        result = await self.db.execute(stmt)
        roles = result.scalars().all()

        # Cache the roles
        if use_cache and roles:
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

        return list(roles)
