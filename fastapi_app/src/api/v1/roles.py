"""
Role management endpoints.

Provides endpoints for role CRUD operations and role assignment.
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from src.api.dependencies import get_db, get_redis_client, get_current_user
from src.models.entity import User
from src.models.schemas import (
    RoleCreate,
    RoleUpdate,
    RoleResponse,
    RoleDetailResponse,
    RolesListResponse,
    RoleAssignmentResponse,
    PermissionCheckResponse,
)
from src.services.role import RoleService
from src.core.exceptions import (
    RoleNotFoundError,
    RoleAlreadyExistsError,
    UserNotFoundError,
    RoleAlreadyAssignedError,
    InsufficientPermissionsError,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/roles", tags=["Roles"])


def check_admin_or_superuser(current_user: User) -> None:
    """
    Helper function to check if user has admin or superuser privileges.
    
    Args:
        current_user: Current authenticated user
        
    Raises:
        HTTPException: If user doesn't have required privileges
    """
    if not current_user.is_superuser:
        # Check if user has admin role
        has_admin = any(
            user_role.role.name == "admin" 
            for user_role in current_user.user_roles
        )
        if not has_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin or superuser access required",
            )


@router.post(
    "",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new role",
    description="Create a new role (requires admin or superuser privileges)",
    responses={
        201: {"description": "Role created successfully"},
        401: {"description": "Unauthorized"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "Role already exists"},
    },
)
async def create_role(
    role_data: RoleCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> RoleResponse:
    """
    Create a new role in the system.
    
    Request body:
    - **name**: Unique role name (required)
    - **description**: Role description (optional)
    
    Requires admin or superuser privileges.
    """
    check_admin_or_superuser(current_user)
    
    try:
        role_service = RoleService(db, redis)
        
        role = await role_service.create_role(
            name=role_data.name,
            description=role_data.description,
        )
        
        logger.info(f"Role created: {role.name} by {current_user.login}")
        
        return RoleResponse.model_validate(role)
        
    except RoleAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error creating role: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while creating role",
        )


@router.get(
    "",
    response_model=RolesListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get all roles",
    description="Returns list of all available roles in the system",
    responses={
        200: {"description": "Roles list retrieved successfully"},
        401: {"description": "Unauthorized"},
    },
)
async def get_roles(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> RolesListResponse:
    """
    Get list of all roles in the system.
    
    Returns:
    - List of all roles with id, name, description, creation date
    - Total count of roles
    
    Requires authentication.
    """
    try:
        role_service = RoleService(db, redis)
        
        roles_list = await role_service.get_roles()
        
        return roles_list
        
    except Exception as e:
        logger.error(f"Error getting roles: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while retrieving roles",
        )


@router.get(
    "/{role_id}",
    response_model=RoleDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get role by ID",
    description="Returns detailed information about a specific role",
    responses={
        200: {"description": "Role information retrieved successfully"},
        401: {"description": "Unauthorized"},
        404: {"description": "Role not found"},
    },
)
async def get_role(
    role_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> RoleDetailResponse:
    """
    Get detailed information about a specific role.
    
    Path parameters:
    - **role_id**: UUID of the role
    
    Returns:
    - Role id, name, description
    - Creation and last update timestamps
    
    Requires authentication.
    """
    try:
        role_service = RoleService(db, redis)
        
        role = await role_service.get_role_by_id(role_id=role_id)
        
        return role
        
    except RoleNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error getting role: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while retrieving role",
        )


@router.put(
    "/{role_id}",
    response_model=RoleDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Update role",
    description="Update role information (requires admin or superuser privileges)",
    responses={
        200: {"description": "Role updated successfully"},
        401: {"description": "Unauthorized"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Role not found"},
    },
)
async def update_role(
    role_id: UUID,
    role_data: RoleUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> RoleDetailResponse:
    """
    Update role information.
    
    Path parameters:
    - **role_id**: UUID of the role to update
    
    Request body (all fields optional):
    - **name**: New role name
    - **description**: New role description
    
    Requires admin or superuser privileges.
    """
    check_admin_or_superuser(current_user)
    
    try:
        role_service = RoleService(db, redis)
        
        role = await role_service.update_role(
            role_id=role_id,
            name=role_data.name,
            description=role_data.description,
        )
        
        logger.info(f"Role updated: {role_id} by {current_user.login}")
        
        return role
        
    except RoleNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail,
        )
    except RoleAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error updating role: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while updating role",
        )


@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete role",
    description="Delete a role from the system (requires admin or superuser privileges)",
    responses={
        204: {"description": "Role deleted successfully"},
        401: {"description": "Unauthorized"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Role not found"},
    },
)
async def delete_role(
    role_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> None:
    """
    Delete a role from the system.
    
    Path parameters:
    - **role_id**: UUID of the role to delete
    
    Warning: This will also remove the role from all users who have it (CASCADE).
    
    Requires admin or superuser privileges.
    """
    check_admin_or_superuser(current_user)
    
    try:
        role_service = RoleService(db, redis)
        
        await role_service.delete_role(role_id=role_id)
        
        logger.info(f"Role deleted: {role_id} by {current_user.login}")
        
    except RoleNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error deleting role: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while deleting role",
        )


@router.post(
    "/{role_id}/users/{user_id}",
    response_model=RoleAssignmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign role to user",
    description="Assign a role to a specific user (requires admin or superuser privileges)",
    responses={
        200: {"description": "Role assigned successfully"},
        401: {"description": "Unauthorized"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Role or user not found"},
        409: {"description": "User already has this role"},
    },
)
async def assign_role(
    role_id: UUID,
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> RoleAssignmentResponse:
    """
    Assign a role to a user.
    
    Path parameters:
    - **role_id**: UUID of the role to assign
    - **user_id**: UUID of the user to receive the role
    
    Returns confirmation with user_id and role_id.
    
    Requires admin or superuser privileges.
    """
    check_admin_or_superuser(current_user)
    
    try:
        role_service = RoleService(db, redis)
        
        result = await role_service.assign_role_to_user(
            role_id=role_id,
            user_id=user_id,
        )
        
        logger.info(f"Role {role_id} assigned to user {user_id} by {current_user.login}")
        
        return result
        
    except (RoleNotFoundError, UserNotFoundError) as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail,
        )
    except RoleAlreadyAssignedError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error assigning role: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while assigning role",
        )


@router.delete(
    "/{role_id}/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove role from user",
    description="Remove a role from a specific user (requires admin or superuser privileges)",
    responses={
        204: {"description": "Role removed successfully"},
        401: {"description": "Unauthorized"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Role or user not found"},
    },
)
async def remove_role(
    role_id: UUID,
    user_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> None:
    """
    Remove a role from a user.
    
    Path parameters:
    - **role_id**: UUID of the role to remove
    - **user_id**: UUID of the user to remove the role from
    
    Requires admin or superuser privileges.
    """
    check_admin_or_superuser(current_user)
    
    try:
        role_service = RoleService(db, redis)
        
        await role_service.remove_role_from_user(
            role_id=role_id,
            user_id=user_id,
        )
        
        logger.info(f"Role {role_id} removed from user {user_id} by {current_user.login}")
        
    except (RoleNotFoundError, UserNotFoundError) as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail,
        )
    except Exception as e:
        logger.error(f"Error removing role: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while removing role",
        )


@router.get(
    "/check",
    response_model=PermissionCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Check user permissions",
    description="Check if current user has a specific role",
    responses={
        200: {"description": "Permission check completed"},
        401: {"description": "Unauthorized"},
    },
)
async def check_permission(
    role: str = Query(..., description="Role name to check"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis_client),
) -> PermissionCheckResponse:
    """
    Check if the current user has a specific role.
    
    Query parameters:
    - **role**: Name of the role to check (required)
    
    Returns:
    - **has_permission**: True if user has the role, False otherwise
    - **user_id**: ID of the current user
    - **role**: Name of the checked role
    
    Note: Superusers are considered to have all roles.
    
    Requires authentication.
    """
    try:
        role_service = RoleService(db, redis)
        
        result = await role_service.check_user_permission(
            user_id=current_user.id,
            role_name=role,
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Error checking permission: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error while checking permission",
        )
